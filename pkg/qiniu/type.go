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
	Name     string `json:"name"`
	NotAfter int64  `json:"not_after"`
	Pri      string `json:"pri"`
	Ca       string `json:"ca"`
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

type UPSSLCertResp struct {
	CertID string `json:"certID"`
}

//内部通用函数

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

	//处理结果并转化为[]byte
	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
