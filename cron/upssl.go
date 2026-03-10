package cron

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
	"github.com/samber/lo"
	"gorm.io/gorm"
)

const (
	ExpirationThreshold = 20 // 证书过期阈值（天）,因为certMagic好像是剩余30天及以上才能续约
	SecondsPerDay       = 24 * 60 * 60
)

type QiniuSSL struct {
	qiniuClient *qiniu.QiniuClient
	sslDAO      *dao.SSLDao
	cmClient    *ssl.CertMagicClient
	emailClient *email.EmailClient
	receiver    string
	duration    time.Duration
}

func NewQiniuSSL() (*QiniuSSL, error) {
	//获取所有相关配置
	conf, err := config.GetConfig()
	if err != nil {
		return nil, err
	}
	qiniuClient := qiniu.NewQiniuClient(
		conf.Qiniu.AccessKey,
		conf.Qiniu.SecretKey,
	)

	emailClient := email.NewEmailClient(
		conf.Email.UserName,
		conf.Email.Password,
		conf.Email.Sender,
		conf.Email.SmtpHost,
		conf.Email.SmtpPort,
	)

	sslDAO, err := dao.NewSSLDao(conf.SSL.DB)
	if err != nil {
		return nil, err
	}

	provider := ssl.NewProvider(
		ssl.Aliyun,
		conf.SSL.Aliyun.AccessKeyID,
		conf.SSL.Aliyun.AccessKeySecret,
		"",
	)

	cmClient, err := ssl.NewCertMagicClient(conf.SSL.Email, conf.SSL.SSLPath, provider)
	if err != nil {
		return nil, err
	}

	return &QiniuSSL{
		qiniuClient: qiniuClient,
		emailClient: emailClient,
		sslDAO:      sslDAO,
		cmClient:    cmClient,
		receiver:    conf.Email.Receiver,
		duration:    conf.SSL.Duration,
	}, nil
}

func (q *QiniuSSL) Start() {
	run := func() error {
		//按照父域名对域名进行分组
		domainGroups, err := q.getDomainGroups()
		if err != nil {
			//发送邮件
			err := q.emailClient.SendEmail([]string{q.receiver}, "七牛云自动报警服务", fmt.Sprintf("域名列表分组失败!:%s", err.Error()), "", nil)
			if err != nil {
				log.Println(err)
				return err
			}
		}

		for domain, list := range domainGroups {
			err := q.startStrategy(context.Background(), domain, list)
			if err != nil {
				// 发送邮件
				err := q.emailClient.SendEmail([]string{q.receiver}, "七牛云自动报警服务", fmt.Sprintf("启动证书失败:%s", err.Error()), "", nil)
				if err != nil {
					log.Println(err)
				}
				continue
			}
		}
		return nil
	}

	//首次启动进行的操作
	//强制为所有的域名申请证书
	for {

		if err := run(); err != nil {
			log.Println(err)
		}

		// 停五分钟等待
		time.Sleep(5 * time.Minute)
	}

}

func (q *QiniuSSL) startStrategy(ctx context.Context, fatherDomain string, domains []string) error {
	var (
		now = time.Now()
	)

	sslCredit, err := q.sslDAO.GetSSLByName(fatherDomain)
	if err != nil {
		return fmt.Errorf("从数据库获取证书失败:%w", err)
	}

	// 如果查询不到直接获取最新的
	if sslCredit.ID == 0 {
		sslCredit, err = q.obtainSSLCredit(ctx, fatherDomain)
		if err != nil {
			return err
		}
	}

	// 如果过期则先删除后获取
	if !checkIfPass(now.Unix(), sslCredit.NotAfter.Unix()) {
		// 删除已经失效的证书
		err = q.sslDAO.DeleteSSL(sslCredit.CertID)
		if err != nil {
			return fmt.Errorf("certID:%s ,删除证书失败:%w", sslCredit.CertID, err)
		}
		sslCredit, err = q.obtainSSLCredit(ctx, fatherDomain)
		if err != nil {
			return err
		}
	}

	// 从七牛云获取证书
	resp, err := q.qiniuClient.GETSSLCertById(sslCredit.CertID)
	if err != nil {
		return fmt.Errorf("certID:%s ,从七牛云获取证书失败:%w", sslCredit.CertID, err)
	}

	// 如果七牛云已经失效则删除并重新获取
	if !checkIfPass(now.Unix(), int64(resp.Cert.NotAfter)) {
		// 删除已经失效的证书
		err = q.sslDAO.DeleteSSL(sslCredit.CertID)
		if err != nil {
			return fmt.Errorf("certID:%s ,删除证书失败:%w", sslCredit.CertID, err)
		}
		sslCredit, err = q.obtainSSLCredit(ctx, fatherDomain)
		if err != nil {
			return err
		}
	}

	var successDomains []dao.Domain
	// 强制开启各个域名的HTTPS
	for _, domain := range domains {
		err := q.qiniuClient.ForceHTTPS(domain, sslCredit.CertID)
		if err != nil {
			return fmt.Errorf("domain:%s, certID:%s, 启用证书失败:%w", domain, sslCredit.CertID, err)
		}
		successDomains = append(successDomains, dao.Domain{Name: domain})

		//防止被七牛云限流
		time.Sleep(5 * time.Second)
	}

	// 获取去重后的结果并保存
	sslCredit.Domains = lo.UniqBy(append(sslCredit.Domains, successDomains...), func(d dao.Domain) string {
		return d.Name
	})

	err = q.sslDAO.SaveSSL(sslCredit)
	if err != nil {
		return fmt.Errorf("domain:%s, certID:%s, 保存或更新证书失败:%w", sslCredit.DomainName, sslCredit.CertID, err)
	}

	return nil
}

func (q *QiniuSSL) obtainSSLCredit(ctx context.Context, fatherDomain string) (*dao.SSL, error) {
	var sslCredit *dao.SSL
	// 尝试获取证书
	certPEM, keyPEM, err := q.cmClient.ObtainCert(ctx, "*."+fatherDomain)
	if err != nil {
		return nil, fmt.Errorf("域名:%s ,获取证书失败:%w", "*."+fatherDomain, err)
	}

	// 解析证书并获取过期时间
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, fmt.Errorf("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// 上传证书
	resp, err := q.qiniuClient.UPSSLCert(keyPEM, certPEM, fatherDomain)
	if err != nil {
		return nil, fmt.Errorf("keyPEM:%s ,certPEM:%s ,Domain:%s,上传证书失败:%w", keyPEM, certPEM, fatherDomain, err)
	}

	// 构建数据模型,注意此时是没有存入任何的子域名的
	sslCredit = &dao.SSL{
		DomainName: fatherDomain,
		CertID:     resp.CertID,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		NotAfter:   cert.NotAfter,
	}

	return sslCredit, nil
}

func checkIfPass(now, t int64) bool {
	// 目标时间与当前时间的差值大于指定时间
	return t-now > ExpirationThreshold*SecondsPerDay
}

// getDomainGroups 获取所有域名，并按父域名分组
func (q *QiniuSSL) getDomainGroups() (map[string][]string, error) {
	domainGroups := make(map[string][]string)
	domainList, err := q.qiniuClient.GetDomainList()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain list: %w", err)
	}

	// 按父域名分组
	for _, domain := range domainList.Domains {
		parentDomain, err := getParentDomain(domain.Name)
		if err != nil {
			fmt.Printf("无法解析域名 %s: %v\n", domain.Name, err)
			continue
		}
		domainGroups[parentDomain] = append(domainGroups[parentDomain], domain.Name)
	}

	// 从需要处理的表格中删除所有已经在符合条件的证书下的域名
	for parentDomain, domains := range domainGroups {
		// 获取已存储的域名及证书过期时间
		notAfter, storedDomains, err := q.sslDAO.GetDomains(parentDomain)
		switch err {
		case nil:
		case gorm.ErrRecordNotFound:
			continue
		default:
			return nil, err
		}

		now := time.Now().Unix()
		// 如果证书未过期，则去除已存储的域名
		if checkIfPass(now, notAfter) {
			domainGroups[parentDomain] = filterUnstoredDomains(domains, storedDomains)
		}
	}

	return domainGroups, nil
}

// filterUnstoredDomains 过滤掉已经存储的域名
func filterUnstoredDomains(allDomains, storedDomains []string) []string {
	storedMap := make(map[string]struct{})
	for _, d := range storedDomains {
		storedMap[d] = struct{}{}
	}

	var result []string
	for _, d := range allDomains {
		if _, exists := storedMap[d]; !exists {
			result = append(result, d)
		}
	}
	return result
}

func getParentDomain(domain string) (string, error) {

	//如果是以.开头的话直接返回,表示是为了某个泛用域名做申请
	if strings.HasPrefix(domain, ".") {
		return strings.TrimPrefix(domain, "."), nil
	}

	// 拆分域名
	parts := strings.Split(domain, ".")
	// 如果域名部分少于两段，说明已经是顶级域名了
	if len(parts) < 2 {
		return "", fmt.Errorf("no parent domain for %s", domain)
	}

	// 组合剩余部分返回
	return strings.Join(parts[1:], "."), nil
}
