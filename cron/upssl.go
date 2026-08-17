package cron

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
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
	"golang.org/x/net/publicsuffix"
)

const (
	ExpirationThreshold = 20 // 证书过期阈值（天）,因为certMagic好像是剩余30天及以上才能续约
	SecondsPerDay       = 24 * 60 * 60

	defaultInterval  = 30 * time.Minute // 配置未提供轮询间隔时的默认值
	groupTimeout     = 10 * time.Minute // 单个证书分组的处理上限，防止 ACME 挑战卡死整轮
	qiniuAPIInterval = 5 * time.Second  // 两次变更之间的间隔，防止被七牛云限流
	alertInterval    = 6 * time.Hour    // 相同内容的告警邮件最小间隔

	protocolHTTP        = "http"
	protocolHTTPS       = "https"
	operatingProcessing = "processing"
)

type QiniuSSL struct {
	qiniuClient *qiniu.QiniuClient
	sslDAO      *dao.SSLDao
	cmClient    *ssl.CertMagicClient
	emailClient *email.EmailClient
	receiver    string
	duration    time.Duration
	forceHTTPS  bool // 是否把 http 请求 301 到 https
	http2       bool // 是否开启 http2

	//告警去重，Start 是单 goroutine 循环，不需要加锁
	lastAlert   string
	lastAlertAt time.Time
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
		forceHTTPS:  conf.SSL.ForceHTTPS,
		http2:       conf.SSL.HTTP2,
	}, nil
}

func (q *QiniuSSL) Start() {
	interval := q.duration
	if interval <= 0 {
		interval = defaultInterval
	}

	for {
		if err := q.run(context.Background()); err != nil {
			log.Printf("本轮处理存在失败:\n%v", err)
			q.alert(fmt.Sprintf("七牛云证书自动化本轮存在失败:\n%v", err))
		}
		time.Sleep(interval)
	}
}

// run 执行完整的一轮：按证书主体名分组 -> 保证证书可用 -> 保证组内域名都绑定该证书。
// 单个分组失败不会影响其它分组，错误统一汇总后返回。
func (q *QiniuSSL) run(ctx context.Context) error {
	//按照证书主体名对域名进行分组
	domainGroups, err := q.getDomainGroups()
	if err != nil {
		return fmt.Errorf("域名列表分组失败: %w", err)
	}

	var errs []error
	for subject, list := range domainGroups {
		//给每个分组设上限，ACME 挑战最长几分钟，卡住也不能拖垮整轮
		groupCtx, cancel := context.WithTimeout(ctx, groupTimeout)
		err := q.startStrategy(groupCtx, subject, list)
		cancel()
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (q *QiniuSSL) alert(msg string) {
	//同样的失败不必每轮都发一封邮件，否则一个长期失败的域名会造成告警轰炸
	if msg == q.lastAlert && time.Since(q.lastAlertAt) < alertInterval {
		return
	}
	if err := q.emailClient.SendEmail([]string{q.receiver}, "七牛云自动报警服务", msg, "", nil); err != nil {
		log.Printf("报警邮件发送失败: %v", err)
		return
	}
	q.lastAlert, q.lastAlertAt = msg, time.Now()
}

// startStrategy 保证 subject 这张证书在七牛云可用，并把 domains 全部绑定到它上面
func (q *QiniuSSL) startStrategy(ctx context.Context, subject string, domains []string) error {
	sslCredit, err := q.ensureCert(ctx, subject)
	if err != nil {
		return err
	}

	leaf, err := parseLeafCert(sslCredit.CertPEM)
	if err != nil {
		return fmt.Errorf("subject:%s, 解析证书失败:%w", subject, err)
	}

	var (
		boundDomains []dao.Domain
		errs         []error
	)
	for _, domain := range domains {
		//先在本地校验覆盖关系：证书盖不到就绝不提交，否则七牛云一定拒绝
		if !certCovers(leaf, domain) {
			errs = append(errs, fmt.Errorf("domain:%s 不在证书 %s(SAN=%v) 的覆盖范围内", domain, subject, leaf.DNSNames))
			continue
		}

		changed, err := q.ensureDomainHTTPS(domain, sslCredit.CertID)
		if err != nil {
			//单个域名失败不影响同组其它域名，下一轮会自动重试
			errs = append(errs, err)
			continue
		}
		boundDomains = append(boundDomains, dao.Domain{Name: domain})

		if changed {
			//防止被七牛云限流
			time.Sleep(qiniuAPIInterval)
		}
	}

	//只记录七牛云侧确认过的绑定关系；内容没变化时不必每轮重写数据库
	bound := lo.UniqBy(boundDomains, func(d dao.Domain) string {
		return d.Name
	})
	if domainsChanged(sslCredit, bound) {
		sslCredit.Domains = bound
		if err := q.sslDAO.SaveSSL(sslCredit); err != nil {
			errs = append(errs, fmt.Errorf("subject:%s, certID:%s, 保存或更新证书失败:%w", subject, sslCredit.CertID, err))
		}
	}

	return errors.Join(errs...)
}

// domainsChanged 判断本轮确认的绑定关系与数据库里已有的记录是否一致
func domainsChanged(sslCredit *dao.SSL, bound []dao.Domain) bool {
	//新申请的证书一定要落库
	if sslCredit.ID == 0 || len(sslCredit.Domains) != len(bound) {
		return true
	}

	stored := make(map[string]struct{}, len(sslCredit.Domains))
	for _, d := range sslCredit.Domains {
		stored[d.Name] = struct{}{}
	}
	for _, d := range bound {
		if _, ok := stored[d.Name]; !ok {
			return true
		}
	}
	return false
}

// ensureCert 确保 subject 对应的证书在本地和七牛云都可用，必要时重新申请并上传
func (q *QiniuSSL) ensureCert(ctx context.Context, subject string) (*dao.SSL, error) {
	sslCredit, err := q.sslDAO.GetSSLByName(subject)
	if err != nil {
		return nil, fmt.Errorf("subject:%s, 从数据库获取证书失败:%w", subject, err)
	}

	now := time.Now().Unix()
	var reason string
	switch {
	case sslCredit.ID == 0:
		reason = "本地无记录"
	case !checkIfPass(now, sslCredit.NotAfter.Unix()):
		reason = "本地记录的证书即将过期"
	default:
		//本地记录有效，再确认七牛云侧证书还在且没过期
		resp, err := q.qiniuClient.GETSSLCertById(sslCredit.CertID)
		switch {
		case err == nil:
			if !checkIfPass(now, int64(resp.Cert.NotAfter)) {
				reason = "七牛云证书即将过期"
			}
		case certGone(err):
			reason = fmt.Sprintf("七牛云证书不可用(%v)", err)
		default:
			//接口临时故障不重建证书，否则一次网络抖动就会多传一张证书
			return nil, fmt.Errorf("subject:%s, certID:%s, 查询七牛云证书失败:%w", subject, sslCredit.CertID, err)
		}
	}

	if reason == "" {
		//记录里的证书内容必须可解析，否则后面的覆盖校验没法做，直接当成需要重建
		if _, err := parseLeafCert(sslCredit.CertPEM); err != nil {
			reason = fmt.Sprintf("本地证书内容损坏(%v)", err)
		}
	}

	if reason == "" {
		return sslCredit, nil
	}

	log.Printf("重新获取证书 subject=%s 原因=%s", subject, reason)
	if sslCredit.ID != 0 {
		if err := q.sslDAO.DeleteSSL(sslCredit.CertID); err != nil {
			return nil, fmt.Errorf("certID:%s ,删除证书失败:%w", sslCredit.CertID, err)
		}
	}
	return q.obtainSSLCredit(ctx, subject)
}

// certGone 判断错误是否表示"这张证书在七牛云上已经用不了了"。
// 只有这种确定性错误才重新申请上传，5xx/网络抖动一律留到下一轮重试。
func certGone(err error) bool {
	if errors.Is(err, qiniu.ErrCertNotFound) {
		return true
	}
	var apiErr *qiniu.APIError
	return errors.As(err, &apiErr) && apiErr.ClientError()
}

// ensureDomainHTTPS 让域名在七牛云侧绑定指定证书，返回本次是否真的提交了变更。
// 判断依据是七牛云返回的实际配置而不是本地数据库，因此天然幂等，失败下一轮会重试。
func (q *QiniuSSL) ensureDomainHTTPS(domain, certID string) (bool, error) {
	info, err := q.qiniuClient.GetDomainInfo(domain)
	if err != nil {
		return false, fmt.Errorf("domain:%s, 查询域名配置失败:%w", domain, err)
	}

	//已经是目标状态，不用再动
	if info.Protocol == protocolHTTPS && info.HTTPS.CertID == certID {
		return false, nil
	}
	if info.OperatingState == operatingProcessing {
		//七牛云的变更是异步生效的，处理中不算失败，下一轮再确认，否则会每轮发一封告警邮件
		log.Printf("domain=%s 七牛云上一次变更(%s)仍在处理中，本轮跳过", domain, info.OperationType)
		return false, nil
	}

	log.Printf("准备开启HTTPS domain=%s cert=%s 当前协议=%s", domain, certID, info.Protocol)
	switch info.Protocol {
	case protocolHTTPS:
		//已经是 https 的域名只能改证书配置，对它调 sslize 会被七牛云拒绝
		err = q.qiniuClient.UpdateHTTPSConf(domain, certID, q.forceHTTPS, q.http2)
	case protocolHTTP:
		err = q.qiniuClient.SSLize(domain, certID, q.forceHTTPS, q.http2)
	default:
		//协议未知时先按 http 处理，被拒绝再按 https 兜底
		if err = q.qiniuClient.SSLize(domain, certID, q.forceHTTPS, q.http2); err != nil {
			if fallbackErr := q.qiniuClient.UpdateHTTPSConf(domain, certID, q.forceHTTPS, q.http2); fallbackErr == nil {
				err = nil
			}
		}
	}
	if err != nil {
		return false, fmt.Errorf("domain:%s, certID:%s, 启用证书失败:%w", domain, certID, err)
	}

	return true, nil
}

func (q *QiniuSSL) obtainSSLCredit(ctx context.Context, subject string) (*dao.SSL, error) {
	// 尝试获取证书，subject 已经是完整的证书主体名（通配符自带 "*."）
	certPEM, keyPEM, err := q.cmClient.ObtainCert(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("域名:%s ,获取证书失败:%w", subject, err)
	}

	// 解析证书并获取过期时间
	cert, err := parseLeafCert(certPEM)
	if err != nil {
		return nil, fmt.Errorf("域名:%s ,解析证书失败:%w", subject, err)
	}

	// 上传证书，common_name 必须与证书真实主体一致
	resp, err := q.qiniuClient.UPSSLCert(keyPEM, certPEM, subject)
	if err != nil {
		return nil, fmt.Errorf("subject:%s ,上传证书失败:%w", subject, err)
	}

	// 构建数据模型,注意此时是没有存入任何的子域名的
	return &dao.SSL{
		DomainName: subject,
		CertID:     resp.CertID,
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		NotAfter:   cert.NotAfter,
	}, nil
}

// parseLeafCert 解析 PEM 链中的第一张证书（叶子证书）
func parseLeafCert(certPEM string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil, errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	return cert, nil
}

func checkIfPass(now, t int64) bool {
	// 目标时间与当前时间的差值大于指定时间
	return t-now > ExpirationThreshold*SecondsPerDay
}

// getDomainGroups 获取所有域名，并按证书主体名分组
func (q *QiniuSSL) getDomainGroups() (map[string][]string, error) {
	domainGroups := make(map[string][]string)
	domainList, err := q.qiniuClient.GetDomainList()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain list: %w", err)
	}

	for _, domain := range domainList.Domains {
		subject, err := certSubject(domain.Name)
		if err != nil {
			log.Printf("跳过无法解析的域名 %s: %v", domain.Name, err)
			continue
		}
		domainGroups[subject] = append(domainGroups[subject], domain.Name)
	}

	return domainGroups, nil
}

// certSubject 计算域名应该使用的证书主体名，同时作为分组 key 与 ACME 申请名。
// 规则：证书永远签给"去掉最左一级 label 后的通配符"，注册域本身只能签单域名证书。
//
//	assets.ota.ccnubox.muxixyz.com -> *.ota.ccnubox.muxixyz.com
//	ota.ccnubox.muxixyz.com        -> *.ccnubox.muxixyz.com
//	forum.muxixyz.com              -> *.muxixyz.com
//	.muxixyz.com（七牛云泛域名）     -> *.muxixyz.com
//	muxixyz.com                    -> muxixyz.com
//
// 这样每个域名一定被自己那张证书覆盖，不会再出现"通配符盖不到父域本身"的情况。
func certSubject(domain string) (string, error) {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	if domain == "" {
		return "", errors.New("空域名")
	}

	// 七牛云泛域名以 "." 开头，含义是该域下的所有一级子域
	if wildcard, ok := strings.CutPrefix(domain, "."); ok {
		if wildcard == "" {
			return "", fmt.Errorf("unsupported domain: %s", domain)
		}
		return "*." + wildcard, nil
	}

	registered, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		return "", fmt.Errorf("unsupported domain: %s: %w", domain, err)
	}
	// 注册域本身没有可用的上级通配符（不可能签 *.com）
	if strings.EqualFold(domain, registered) {
		return domain, nil
	}

	_, parent, _ := strings.Cut(domain, ".")
	return "*." + parent, nil
}

// certCovers 按 RFC 6125 判断证书能否覆盖该域名
func certCovers(cert *x509.Certificate, domain string) bool {
	domain = strings.TrimSuffix(strings.TrimSpace(domain), ".")
	// 七牛云泛域名 ".x.com" 等价于 "*.x.com"
	if wildcard, ok := strings.CutPrefix(domain, "."); ok {
		domain = "*." + wildcard
	}

	for _, name := range cert.DNSNames {
		if matchDNSName(name, domain) {
			return true
		}
	}
	return false
}

// matchDNSName 判断证书里的一个 SAN 是否匹配目标域名，通配符只匹配一级 label
func matchDNSName(certName, domain string) bool {
	if strings.EqualFold(certName, domain) {
		return true
	}

	suffix, ok := strings.CutPrefix(certName, "*.")
	if !ok {
		return false
	}

	label, parent, found := strings.Cut(domain, ".")
	if !found || label == "" || strings.Contains(label, "*") {
		return false
	}
	return strings.EqualFold(parent, suffix)
}
