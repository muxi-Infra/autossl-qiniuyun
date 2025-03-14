package ssl

import (
	"fmt"
	"github.com/caddyserver/certmagic"
	"github.com/libdns/alidns"
	"github.com/libdns/cloudflare"
	"github.com/libdns/tencentcloud"
)

const (
	Aliyun     = "aliyun"
	Tencent    = "tencent"
	CloudFlare = "cloudflare"
)

func NewDNSProvider(p Provider) (certmagic.DNSProvider, error) {
	switch p.Platform {
	case Aliyun:
		return &alidns.Provider{
			AccKeyID:     p.AccessKeyID,
			AccKeySecret: p.AccessKeySecret,
		}, nil
	case Tencent:
		return &tencentcloud.Provider{
			SecretId:  p.AccessKeyID,
			SecretKey: p.AccessKeySecret,
		}, nil
	case CloudFlare:
		return &cloudflare.Provider{
			APIToken: p.Token,
		}, nil
	default:
		//显示返回不支持的平台
		return nil, fmt.Errorf("Unsupported platform")
	}
}

type Provider struct {
	Platform        string `json:"platform"`
	AccessKeyID     string `json:"access_key_id"`
	AccessKeySecret string `json:"access_key_secret"`
	Token           string `json:"token"` //对于某些只需要单个token的服务(可以考虑复用AccessKeySercet)
}

func NewProvider(platform, accessKeyID, accessKeySecret, token string) Provider {
	return Provider{
		AccessKeyID:     accessKeyID,
		AccessKeySecret: accessKeySecret,
		Token:           token,
		Platform:        platform,
	}
}
