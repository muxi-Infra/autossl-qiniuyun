package ssl

import (
	"context"
	"fmt"

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

// ObtainCert 获取 domain 的证书 PEM。
// 顺序：本地没有就申请 -> 接近过期才续期 -> 从存储载入。
// 这样重复调用不会浪费 ACME 额度（Let's Encrypt 对同一组域名每周只允许 5 张重复证书），
// 同时首次申请也不会像以前那样因为直接 Renew 找不到已有证书而失败。
func (c *CertMagicClient) ObtainCert(ctx context.Context, domain string) (string, string, error) {
	// 本地存储已有该证书时是 no-op
	if err := c.cm.ObtainCertSync(ctx, domain); err != nil {
		return "", "", fmt.Errorf("申请证书失败: %w", err)
	}

	// force=false：只有进入续期窗口才会真正向 CA 发起请求
	if err := c.cm.RenewCertSync(ctx, domain, false); err != nil {
		return "", "", fmt.Errorf("续期证书失败: %w", err)
	}

	// 从存储载入最新证书（Renew 不会更新内存缓存，这里读的是存储）
	cert, err := c.cm.CacheManagedCertificate(ctx, domain)
	if err != nil {
		return "", "", fmt.Errorf("加载证书失败: %w", err)
	}

	certPEM, keyPEM, err := c.convertCertToPEM(cert.Certificate)
	if err != nil {
		return "", "", err
	}

	return certPEM, keyPEM, nil
}
