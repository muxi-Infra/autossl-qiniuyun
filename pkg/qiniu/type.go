package qiniu

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/qiniu/go-sdk/v7/auth"
	"io"
	"net/http"
	"net/url"
	"reflect"
)

// 获取域名列表请求,这里只用了一个limit字段,因为不怎么用得到其他的字段，具体请看：https://developer.qiniu.com/fusion/4246/the-domain-name#10
type GetDomainReq struct {
	Limit int `json:"limit"`
}

// 域名列表响应（对应 JSON 根对象）
type GetDomainResp struct {
	Domains []Domain `json:"domains"`
}

// Domain 结构体（对应 domains 数组中的每个对象）
type Domain struct {
	Name     string `json:"name"`     //域名
	CreateAt string `json:"createAt"` // 域名创建时间，格式:RFC3339
	Product  string `json:"product"`  // cdn / dcdn
	Type     string `json:"type"`     // normal / pan，只有 normal 才能 sslize/httpsconf
}

type UPSSLCertReq struct {
	Name       string `json:"name"`
	CommonName string `json:"common_name"`
	Pri        string `json:"pri"`
	Ca         string `json:"ca"`
}

type GetSSLCertListReq struct {
	Limit int `json:"limit"`
}

type GetSSLCertByIDResp struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
	Cert  struct {
		Certid           string   `json:"certid"`
		Name             string   `json:"name"`
		Uid              int      `json:"uid"`
		CommonName       string   `json:"common_name"`
		Dnsnames         []string `json:"dnsnames"`
		CreateTime       int      `json:"create_time"`
		NotBefore        int      `json:"not_before"`
		NotAfter         int      `json:"not_after"`
		Orderid          string   `json:"orderid"`
		ProductShortName string   `json:"product_short_name"`
		ProductType      string   `json:"product_type"`
		CertType         string   `json:"cert_type"`
		Encrypt          string   `json:"encrypt"`
		EncryptParameter string   `json:"encryptParameter"`
		Enable           bool     `json:"enable"`
		ChildOrderId     string   `json:"child_order_id"`
		State            string   `json:"state"`
		AutoRenew        bool     `json:"auto_renew"`
		Renewable        bool     `json:"renewable"`
		Ca               string   `json:"ca"`
		Pri              string   `json:"pri"`
	} `json:"cert"`
}
type GetSSLCertListResp struct {
	Certs []Cert `json:"certs"`
}
type GetSSLCertById struct {
	Certs []Cert `json:"certs"`
}
type Cert struct {
	CertId   string `json:"certid"`
	Name     string `json:"name"`
	NotAfter int64  `json:"not_after"`
}

type ForceHTTPSReq struct {
	CertId      string `json:"certid"`
	ForceHttps  bool   `json:"forceHttps"`
	Http2Enable bool   `json:"http2Enable"`
}

// GetDomainInfoResp 域名详情，只保留判断 HTTPS 配置所需的字段
// 文档：https://developer.qiniu.com/fusion/4246/the-domain-name
type GetDomainInfoResp struct {
	Code           int    `json:"code"`
	Error          string `json:"error"`
	Name           string `json:"name"`
	Protocol       string `json:"protocol"`       // http / https
	OperatingState string `json:"operatingState"` // success / processing / failed
	OperationType  string `json:"operationType"`
	HTTPS          struct {
		CertID      string `json:"certId"`
		ForceHttps  bool   `json:"forceHttps"`
		Http2Enable bool   `json:"http2Enable"`
	} `json:"https"`
}

type UPSSLCertResp struct {
	Code   int    `json:"code"`
	Error  string `json:"error"`
	CertID string `json:"certid"`
}

//内部通用函数

// ErrCertNotFound 七牛云上找不到该证书（被手动删除等）
var ErrCertNotFound = errors.New("证书在七牛云上不存在")

// APIError 七牛云返回的非 2xx 响应，调用方可以用 errors.As 精确区分"证书不存在"与"接口临时故障"
type APIError struct {
	Method     string
	Path       string
	StatusCode int
	Body       string
}

func (e *APIError) Error() string {
	//响应体可能带上传时提交的证书内容，只保留前 256 字节，避免私钥进日志和报警邮件
	body := e.Body
	if len(body) > 256 {
		body = body[:256] + "...(truncated)"
	}
	return fmt.Sprintf("七牛云接口失败 %s %s: status=%d body=%s", e.Method, e.Path, e.StatusCode, body)
}

// ClientError 4xx，表示请求本身有问题（参数非法、资源不存在），重试也不会成功
func (e *APIError) ClientError() bool {
	return e.StatusCode >= http.StatusBadRequest && e.StatusCode < http.StatusInternalServerError
}

// bizResp 七牛云部分接口在 HTTP 200 的同时用 body 里的 code/error 表达失败
type bizResp struct {
	Code  int    `json:"code"`
	Error string `json:"error"`
}

// checkBizError 解析业务错误码。
// 注意七牛云成功时也可能返回 {"code":200,"error":"success"}，所以只认非 0 且非 200 的 code，
// 不能直接拿 error 字段是否为空来判断。
func checkBizError(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	var resp bizResp
	if err := json.Unmarshal(data, &resp); err != nil {
		//成功响应可能是空体或非对象，解析不了就不当作失败
		return nil
	}
	if resp.Code != 0 && resp.Code != http.StatusOK {
		return fmt.Errorf("七牛云返回业务错误: code=%d error=%s", resp.Code, resp.Error)
	}
	return nil
}

// 发送 HTTP 请求，自动处理参数方式
func (c *QiniuClient) newReq(method, path string, data any) ([]byte, error) {
	var body io.Reader
	urlParams := url.Values{}

	// 解析 struct 并根据 method 选择传参方式
	if data != nil {

		values, err := c.structToMap(data)
		if err != nil {
			return nil, err
		}

		if method == http.MethodGet {
			for k, v := range values {
				urlParams.Set(k, v)
			}
			path = fmt.Sprintf("%s?%s", path, urlParams.Encode())
		} else {
			jsonData, err := json.Marshal(data)
			if err != nil {
				return nil, err
			}
			body = bytes.NewBuffer(jsonData)
		}
	}

	// 构造请求
	req, err := http.NewRequest(method, QiniuBaseUrl+path, body)
	if err != nil {
		return nil, err
	}

	//选择请求头
	if method == http.MethodGet {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	} else {
		//如果是非get的话则设置为json
		req.Header.Set("Content-Type", "application/json")
	}

	// 添加 Token 认证
	if err := c.qiniuClient.AddToken(auth.TokenQBox, req); err != nil {
		return nil, err
	}

	//发送请求
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	//必须关闭，否则 keep-alive 连接无法归还连接池，长跑会耗尽 fd
	defer resp.Body.Close()

	//处理结果并转化为[]byte
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	//七牛云的错误必须显式暴露：以前不看状态码，失败会被当成成功，
	//导致"证书没绑上却记录成功"，且之后永远不再重试
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, &APIError{Method: method, Path: path, StatusCode: resp.StatusCode, Body: string(result)}
	}

	return result, nil
}

func (c *QiniuClient) structToMap(data any) (map[string]string, error) {
	result := make(map[string]string)

	v := reflect.ValueOf(data)
	if v.Kind() != reflect.Struct {
		return nil, errors.New("data must be a struct")
	}

	t := v.Type()
	for i := 0; i < v.NumField(); i++ {
		field := t.Field(i)
		value := v.Field(i)

		// 跳过空值
		if value.IsZero() {
			continue
		}

		// 获取 JSON tag 作为 key
		key := field.Tag.Get("json")
		if key == "" {
			key = field.Name
		}

		// 转成字符串
		result[key] = fmt.Sprintf("%v", value.Interface())
	}

	return result, nil
}
