package qiniu

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/qiniu/go-sdk/v7/auth"
)

func NewQiniuClient(accessKey string, secretKey string) *QiniuClient {
	return &QiniuClient{
		qiniuClient: auth.New(accessKey, secretKey),
		//必须有超时：默认 client 无超时，七牛云卡住会让整轮任务永远挂起
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

const QiniuBaseUrl = "https://api.qiniu.com"

type QiniuClient struct {
	qiniuClient *auth.Credentials
	client      *http.Client
}

func (c *QiniuClient) GetDomainList() (GetDomainResp, error) {
	var resp GetDomainResp
	data, err := c.newReq(http.MethodGet, "/domain", GetDomainReq{Limit: 1000})
	if err != nil {
		return GetDomainResp{}, err
	}

	err = json.Unmarshal(data, &resp)
	if err != nil {
		return GetDomainResp{}, err
	}
	return resp, nil
}

// UPSSLCert 上传ssl证书
// commonName 必须是证书真实的主体名（通配符证书就要带 "*."），否则七牛云侧的证书信息
// 与证书内容不一致，绑定域名时会被判定为不匹配。
func (c *QiniuClient) UPSSLCert(pri, ca, commonName string) (UPSSLCertResp, error) {
	var resp UPSSLCertResp
	//证书名仅用于控制台展示，七牛云对 "*" 的支持不明确，这里统一替换
	name := strings.ReplaceAll(commonName, "*", "wildcard")
	data, err := c.newReq(http.MethodPost, "/sslcert", UPSSLCertReq{Name: name, CommonName: commonName, Pri: pri, Ca: ca})
	if err != nil {
		return UPSSLCertResp{}, err
	}

	err = json.Unmarshal(data, &resp)
	if err != nil {
		return UPSSLCertResp{}, err
	}
	if resp.CertID == "" {
		return UPSSLCertResp{}, fmt.Errorf("上传证书未返回 certID: code=%d error=%s", resp.Code, resp.Error)
	}
	return resp, nil
}

// 获取ssl证书列表
func (c *QiniuClient) GETSSLCertList() (GetSSLCertListResp, error) {
	var resp GetSSLCertListResp
	data, err := c.newReq(http.MethodGet, "/sslcert", GetSSLCertListReq{Limit: 500})
	if err != nil {
		return GetSSLCertListResp{}, err
	}

	err = json.Unmarshal(data, &resp)
	if err != nil {
		return GetSSLCertListResp{}, err
	}
	return resp, nil
}

// 使用certId获取ssl证书
func (c *QiniuClient) GETSSLCertById(certId string) (GetSSLCertByIDResp, error) {
	var resp GetSSLCertByIDResp
	data, err := c.newReq(http.MethodGet, "/sslcert/"+certId, nil)
	if err != nil {
		return GetSSLCertByIDResp{}, err
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return GetSSLCertByIDResp{}, err

	}
	//证书被删除时七牛云可能返回 200 + 业务错误码，必须显式判断
	if bizErr := checkBizError(data); bizErr != nil || resp.Cert.Certid == "" {
		return GetSSLCertByIDResp{}, fmt.Errorf("certID=%s (%v): %w", certId, bizErr, ErrCertNotFound)
	}
	return resp, nil
}

// 删除证书
func (c *QiniuClient) RemoveSSLCert(certId string) error {
	_, err := c.newReq(http.MethodPost, "/sslcert/"+certId, nil)
	if err != nil {
		return err
	}
	return nil
}

// GetDomainInfo 获取单个域名的详情，用于判断它当前是否已经绑定了期望的证书。
// 以七牛云的真实状态为准，而不是以本地数据库的记录为准。
func (c *QiniuClient) GetDomainInfo(name string) (GetDomainInfoResp, error) {
	var resp GetDomainInfoResp
	data, err := c.newReq(http.MethodGet, "/domain/"+name, nil)
	if err != nil {
		return GetDomainInfoResp{}, err
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		return GetDomainInfoResp{}, err
	}
	if err := checkBizError(data); err != nil {
		return GetDomainInfoResp{}, fmt.Errorf("查询域名 %s 详情失败: %w", name, err)
	}
	return resp, nil
}

// SSLize 把 http 域名转换为 https 并绑定证书，只适用于当前协议是 http 的域名
func (c *QiniuClient) SSLize(name, certID string, forceHTTPS, http2 bool) error {
	data, err := c.newReq(http.MethodPut, "/domain/"+name+"/sslize", ForceHTTPSReq{
		CertId:      certID,
		ForceHttps:  forceHTTPS,
		Http2Enable: http2,
	})
	if err != nil {
		return err
	}
	return checkBizError(data)
}

// UpdateHTTPSConf 修改已经是 https 的域名的证书配置。
// 对已是 https 的域名调用 sslize 会被七牛云拒绝，必须走这个接口。
func (c *QiniuClient) UpdateHTTPSConf(name, certID string, forceHTTPS, http2 bool) error {
	data, err := c.newReq(http.MethodPut, "/domain/"+name+"/httpsconf", ForceHTTPSReq{
		CertId:      certID,
		ForceHttps:  forceHTTPS,
		Http2Enable: http2,
	})
	if err != nil {
		return err
	}
	return checkBizError(data)
}
