package cron

import (
	"fmt"
	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
	"time"
)

type DomainDAO interface {
	GetDomainList() ([]dao.Domain, error)
	SaveDomainList(domainList []dao.Domain) error
}

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

		//获取要申领的域名列表
		domains, err := q.getFilteredDomains()
		if err != nil {
			return
		}

		//存储到失败的map里面
		var failMap = make(map[int][]DomainWithCert)
		for _, domain := range domains {
			code, err := StartStrategy(StartAll, &domain)
			if err != nil {
				failMap[code] = append(failMap[code], domain)
				return
			}
		}

		var errs []ErrWithDomain

		//遍历failMap
		for k, v := range failMap {
			for _, domain := range v {
				_, err := StartStrategy(k, &domain)
				if err != nil {
					errs = append(errs, ErrWithDomain{
						err:    fmt.Errorf(":%v", err),
						domain: domain.Name,
					})
				}
			}
		}

		//如果有错误则收集并发送最终报文
		if len(errs) > 0 {
			//发送邮件
			err := emailClient.SendEmail([]string{receiver}, "七牛云自动报警服务", "", q.generateErrorReportHTML(errs), nil)
			if err != nil {
				return
			}
		}

	}
}

func (q *QiniuSSL) initConfig() {

	//获取所有相关配置
	cron := config.GetCronConfig()
	//停止一段时间防止被识别为攻击
	//time.Sleep(cron.Duration)
	//当出现更改时才进行修改
	if cron.QiniuConf.Changed {
		qiniuClient = qiniu.NewQiniuClient(cron.AccessKey, cron.SecretKey)
	}

	if cron.EmailConf.Changed {
		emailClient = email.NewEmailClient(cron.UserName, cron.Password, cron.Sender, cron.SmtpHost, cron.SmtpPort)
	}

	if cron.SSLConf.Changed {
		provider := ssl.NewProvider(ssl.Aliyun, cron.Aliyun.AccessKeyID, cron.Aliyun.AccessKeySecret, "")
		var err error
		cmClient, err = ssl.NewCertMagicClient(cron.Email, cron.SSLPath, provider)
		if err != nil {
			// TODO
			return
		}
		receiver = cron.Receiver
	}

}

func (q *QiniuSSL) getFilteredDomains() ([]DomainWithCert, error) {

	domainList, err := qiniuClient.GetDomainList()
	if err != nil {
		return []DomainWithCert{}, nil
	}

	//获取当前存储的所有的证书
	certList, err := qiniuClient.GETSSLCertList()
	if err != nil {
		return []DomainWithCert{}, nil
	}

	//去除所有的当前并不需要进行操作的

	// 证书映射表 (域名 -> 证书)
	certMap := make(map[string]qiniu.Cert)
	for _, cert := range certList.Certs {
		certMap[cert.Name] = cert
	}

	// 计算 30 天后的时间
	cutoffTime := time.Now().Add(30 * 24 * time.Hour).Unix()

	// 筛选符合条件的域名
	var filteredDomains []DomainWithCert
	for _, domain := range domainList.Domains {
		cert, exists := certMap[domain.Name]
		if exists {
			// 仅保留过期时间 <= 30 天的证书
			if cert.NotAfter <= int(cutoffTime) {
				filteredDomains = append(filteredDomains, DomainWithCert{
					Name:      domain.Name,
					OldCertID: cert.CertId,
				})
			}
		} else {
			filteredDomains = append(filteredDomains, DomainWithCert{
				Name: domain.Name,
			})
		}
	}

	return filteredDomains, nil
}

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
						<th>域名</th>
						<th>错误信息</th>
					</tr>
	`

	for _, e := range errs {
		html += fmt.Sprintf(`
			<tr>
				<td>%s</td>
				<td>%s</td>
			</tr>`, e.domain, e.err.Error())
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
	err    error
	domain string
}
type DomainWithCert struct {
	Name      string
	OldCertID string
	CertID    string
	KeyPEM    string
	CertPEM   string
}

//Let's Encrypt 相关限流规则
//单个注册账号的证书请求限制
//
//50 个证书/每 3 小时（对于不同的主域名，不管多少子域名）。
//例如，你在 3 小时内尝试为 51 个不同的域名申请证书，第 51 个请求会被拒绝。
//同一主域名的证书限制
//
//50 个证书/每周（同一个主域名及其子域名的总和）。
//例如，example.com 及其 *.example.com 和 sub.example.com 在 7 天内只能申请 50 个证书。
//注册账号创建限制
//
//10 个账户/每 3 小时（基于相同 IP 地址）。
//如果你试图短时间内创建多个 Let's Encrypt 账户，也可能被限制。
//重复证书申请限制
//
//5 次相同证书/每周（即相同的域名列表）。
//例如，如果你反复申请 a.example.com 和 b.example.com，最多可以在 7 天内成功 5 次。
//解决方案
//使用通配符证书（Wildcard）
//
//申请 *.example.com 而不是单独为 a.example.com、b.example.com 申请多个证书。
//需要使用 DNS-01 方式验证域名。
//合并多个域名到一个证书
//
//Let's Encrypt 允许一个证书包含多个域名（SAN）。
//例如，一个证书可以同时包含 example1.com、example2.com、example3.com，避免单独申请多个证书。
//分批申请
//
//计划性地分散申请请求，避免在短时间内触发限制。
