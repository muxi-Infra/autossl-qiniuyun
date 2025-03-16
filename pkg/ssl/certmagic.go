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
	//certmagic.DefaultACME.CA = certmagic.LetsEncryptStagingCA
	certmagic.DefaultACME.DNS01Solver = &certmagic.DNS01Solver{
		DNSManager: certmagic.DNSManager{
			DNSProvider: dnsProvider,
		},
	}

	// 创建 CertMagic 配置
	cm := certmagic.NewDefault()
	cm.Storage = &certmagic.FileStorage{Path: path}

	return &CertMagicClient{cm: cm}, nil
}

type CertMagicClient struct {
	cm *certmagic.Config
}

// 获取证书
func (c *CertMagicClient) ObtainCert(ctx context.Context, domain string) (string, string, error) {

	err := c.cm.ObtainCertSync(ctx, domain)
	if err != nil {
		return "", "", err
	}

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
