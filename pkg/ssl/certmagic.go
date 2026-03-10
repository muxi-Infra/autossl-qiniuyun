package ssl

import (
	"context"

	"github.com/caddyserver/certmagic"
)

// NewCertMagicClient 生成 CertMagicClient，用户可以自定义传入 libdns 兼容的 Provider
func NewCertMagicClient(email, path string, provider Provider) (*CertMagicClient, error) {
	if email == "" {
		email = "admin@yourdomain.com"
	}

	//根据配置去获取dns配置
	dnsProvider, err := NewDNSProvider(provider)
	if err != nil {
		return nil, err
	}

	// 配置 CertMagic
	certmagic.DefaultACME.Email = email
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: dnsProvider,
		},
	}
	//更改默认的路径
	certmagic.Default.Storage = &certmagic.FileStorage{
		Path: path,
	}
	// 创建 CertMagic 配置
	cm := certmagic.NewDefault()
	cm.Storage = &certmagic.FileStorage{Path: path}

	return &CertMagicClient{cm: cm}, nil
}

type CertMagicClient struct {
	cm *certmagic.Config
}

// 强制获取证书（不走缓存）
func (c *CertMagicClient) ObtainCert(ctx context.Context, domain string) (string, string, error) {

	err := c.cm.RenewCertSync(ctx, domain, false) // false 表示不进入预留的过期检查逻辑
	if err != nil {
		return "", "", err
	}

	// 获取最新申请到的证书（此时缓存已更新）
	cert, err := c.cm.CacheManagedCertificate(ctx, domain)
	if err != nil {
		return "", "", err
	}

	certPEM, keyPEM, err := c.convertCertToPEM(cert.Certificate)
	if err != nil {
		return "", "", err
	}

	return certPEM, keyPEM, nil
}
