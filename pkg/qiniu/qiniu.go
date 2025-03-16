package qiniu

import (
	"encoding/json"
	"github.com/qiniu/go-sdk/v7/auth"
	"net/http"
)

func NewQiniuClient(accessKey string, secretKey string) *QiniuClient {
	return &QiniuClient{
		qiniuClient: auth.New(accessKey, secretKey),
		client:      http.DefaultClient,
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

// 上传ssl证书
func (c *QiniuClient) UPSSLCert(pri, ca, name string) (UPSSLCertResp, error) {
	var resp UPSSLCertResp
	data, err := c.newReq(http.MethodPost, "/sslcert", UPSSLCertReq{Name: name, CommonName: name, Pri: pri, Ca: ca})
	if err != nil {
		return UPSSLCertResp{}, err
	}

	err = json.Unmarshal(data, &resp)
	if err != nil {
		return UPSSLCertResp{}, err
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
	//如果存在则不会报错,这里没有去查错误码 TODO 使用错误码进行精确对应
	data, err := c.newReq(http.MethodGet, "/sslcert/"+certId, nil)
	if err != nil {
		return GetSSLCertByIDResp{}, err
	}
	err = json.Unmarshal(data, &resp)
	if err != nil {
		return GetSSLCertByIDResp{}, err

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

// 修改绑定的证书并开启https
func (c *QiniuClient) ForceHTTPS(name, certID string) error {
	_, err := c.newReq(http.MethodPut, "/domain/"+name+"/sslize", ForceHTTPSReq{
		CertId:      certID,
		ForceHttps:  false, //默认关闭强制https
		Http2Enable: false, //默认关闭http2强制
	})
	if err != nil {
		return err
	}
	return nil
}
