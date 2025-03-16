package cron

import (
	"fmt"
	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
	"golang.org/x/net/publicsuffix"
	"gorm.io/gorm"
	"time"
)

type QiniuSSL struct {
}

func NewQiniuSSL() *QiniuSSL {
	return &QiniuSSL{}
}

func (q *QiniuSSL) Start() {
	//首次启动进行的操作

	//强制为所有的域名申请证书
	for {

		//初始化配置
		q.initConfig()

		//按照父域名对域名进行分组
		domainGroups, err := q.getDomainGroups()
		if err != nil {
			//发送邮件
			err := emailClient.SendEmail([]string{receiver}, "七牛云自动报警服务", fmt.Sprintf("域名列表分组失败!:%s", err.Error()), "", nil)
			if err != nil {
				return
			}
			continue
		}

		//存储到失败的map里面
		var failMap = make(map[int]*DomainWithCert)
		for k, v := range domainGroups {
			var d = DomainWithCert{
				Domains:      v,
				FatherDomain: k,
			}
			code, err := StartStrategy(StartAll, &d)
			if err != nil {
				failMap[code] = &d
			}
		}

		var errs []ErrWithDomain

		//遍历failMap
		for k, v := range failMap {
			_, err := StartStrategy(k, v)
			if err != nil {
				errs = append(errs, ErrWithDomain{
					err:     err,
					Domains: v.Domains,
				})
			}

		}

		//如果有错误则收集并发送最终报文

		if len(errs) > 0 {
			//发送邮件
			err := emailClient.SendEmail([]string{receiver}, "七牛云自动报警服务", "", q.generateErrorReportHTML(errs), nil)
			if err != nil {
				// TODO 如果邮件也失败了的话应当输出到日志系统里
			}
		}

	}
}

func (q *QiniuSSL) initConfig() {

	//获取所有相关配置
	cron := config.GetCronConfig()

	//停止一段时间防止被识别为攻击
	time.Sleep(cron.Duration)

	//当出现更改时才进行修改
	if cron.QiniuConf.Changed {
		qiniuClient = qiniu.NewQiniuClient(cron.AccessKey, cron.SecretKey)
	}

	if cron.EmailConf.Changed {
		emailClient = email.NewEmailClient(cron.UserName, cron.Password, cron.Sender, cron.SmtpHost, cron.SmtpPort)
	}

	if cron.SSLConf.Changed {
		var err error
		sslDAO, err = dao.NewSSLDao(cron.DB)
		if err != nil {
			// TODO
			return
		}

		provider := ssl.NewProvider(ssl.Aliyun, cron.Aliyun.AccessKeyID, cron.Aliyun.AccessKeySecret, "")

		cmClient, err = ssl.NewCertMagicClient(cron.Email, cron.SSLPath, provider)
		if err != nil {
			// TODO
			return
		}
		receiver = cron.Receiver
	}
	now = time.Now().Unix()

}

const (
	ExpirationThreshold = 30 // 证书过期阈值（天）
	SecondsPerDay       = 24 * 60 * 60
)

// getDomainGroups 获取所有域名，并按父域名分组
func (q *QiniuSSL) getDomainGroups() (map[string][]string, error) {
	domainGroups := make(map[string][]string)
	domainList, err := qiniuClient.GetDomainList()
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
		certTime, storedDomains, err := sslDAO.GetDomains(parentDomain)
		switch err {
		case nil:
		case gorm.ErrRecordNotFound:
			continue
		default:
			return nil, err
		}

		now := time.Now().Unix()
		// 如果证书未过期，则去除已存储的域名
		if now-certTime < ExpirationThreshold*SecondsPerDay {
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

// getParentDomain 获取父级域名
func getParentDomain(domain string) (string, error) {
	return publicsuffix.EffectiveTLDPlusOne(domain)
}

// 生成错误报告的html
func (q *QiniuSSL) generateErrorReportHTML(errs []ErrWithDomain) string {
	html := `
		<!DOCTYPE html>
		<html lang="zh">
		<head>
			<meta charset="UTF-8">
			<meta name="viewport" content="width=device-width, initial-scale=1.0">
			<title>失败域名报告</title>
			<style>
				body { font-family: Arial, sans-serif; margin: 20px; padding: 20px; }
				.container { max-width: 600px; margin: auto; }
				h2 { color: #d9534f; text-align: center; }
				table { width: 100%%; border-collapse: collapse; margin-top: 20px; }
				th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
				th { background-color: #f8d7da; }
				tr:nth-child(even) { background-color: #f2f2f2; }
				.footer { margin-top: 20px; font-size: 14px; color: #777; text-align: center; }
			</style>
		</head>
		<body>
			<div class="container">
				<h2>失败域名报告</h2>
				<table>
					<tr>
						<th>域名列表</th>
						<th>错误信息</th>
					</tr>
	`

	for _, e := range errs {
		html += fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
			</tr>`, fmt.Sprintf("%v", e.Domains), e.err.Error())
	}

	html += `
				</table>
				<div class="footer">本邮件由系统自动发送，请勿回复。</div>
			</div>
		</body>
		</html>
	`

	return html
}

type ErrWithDomain struct {
	err     error
	Domains []string
}

type DomainWithCert struct {
	Domains      []string //域名列表
	FatherDomain string   //父域名
	OldCertId    string   //旧证书的id
	CertId       string   //证书id
	CertPEM      string   //证书的内容
	KeyPEM       string   //证书的内容
}
