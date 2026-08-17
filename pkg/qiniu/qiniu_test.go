package qiniu

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/qiniu/go-sdk/v7/auth"
)

// redirectTransport 把发往 api.qiniu.com 的请求改投到测试服务器，避免为了测试改动生产代码
type redirectTransport struct{ target *url.URL }

func (t redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = t.target.Scheme
	req.URL.Host = t.target.Host
	return http.DefaultTransport.RoundTrip(req)
}

func newTestClient(t *testing.T, handler http.HandlerFunc) *QiniuClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	target, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("解析测试服务器地址失败: %v", err)
	}
	return &QiniuClient{
		qiniuClient: auth.New("test-ak", "test-sk"),
		client:      &http.Client{Transport: redirectTransport{target: target}},
	}
}

func TestCheckBizError(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "空响应体", body: "", wantErr: false},
		{name: "空对象", body: "{}", wantErr: false},
		{name: "成功也可能带 code200", body: `{"code":200,"error":"success"}`, wantErr: false},
		{name: "业务错误码", body: `{"code":400611,"error":"cert not match domain"}`, wantErr: true},
		{name: "非 JSON 响应", body: "OK", wantErr: false},
		{name: "正常域名详情", body: `{"name":"x.com","protocol":"https"}`, wantErr: false},
	}

	for _, tt := range tests {
		err := checkBizError([]byte(tt.body))
		if (err != nil) != tt.wantErr {
			t.Errorf("%s: checkBizError(%q) err=%v, 期望出错=%v", tt.name, tt.body, err, tt.wantErr)
		}
	}
}

// TestSSLizeSurfacesErrors 这两种失败以前都会被当成成功，是线上故障的直接原因
func TestSSLizeSurfacesErrors(t *testing.T) {
	t.Run("HTTP 4xx 必须报错", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"code":400611,"error":"cert not match domain"}`))
		})

		err := c.SSLize("assets.ota.ccnubox.muxixyz.com", "certid", false, false)
		if err == nil {
			t.Fatal("七牛云返回 400，SSLize 必须返回错误")
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || !apiErr.ClientError() {
			t.Errorf("错误类型不对: %v", err)
		}
	})

	t.Run("200 + 业务错误码必须报错", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"code":400611,"error":"cert not match domain"}`))
		})

		if err := c.SSLize("assets.ota.ccnubox.muxixyz.com", "certid", false, false); err == nil {
			t.Fatal("七牛云返回业务错误码，SSLize 必须返回错误")
		}
	})

	t.Run("成功不应报错", func(t *testing.T) {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut {
				t.Errorf("期望 PUT，实际 %s", r.Method)
			}
			_, _ = w.Write([]byte(`{}`))
		})

		if err := c.SSLize("assets.ota.ccnubox.muxixyz.com", "certid", false, false); err != nil {
			t.Fatalf("正常响应不应报错: %v", err)
		}
	})
}

func TestGETSSLCertByIdDetectsMissingCert(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":404,"error":"cert not found"}`))
	})

	_, err := c.GETSSLCertById("6a831305cb904e2c369c37a9")
	if !errors.Is(err, ErrCertNotFound) {
		t.Fatalf("证书不存在必须返回 ErrCertNotFound，实际: %v", err)
	}
}

func TestUPSSLCertRejectsEmptyCertID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})

	if _, err := c.UPSSLCert("key", "cert", "*.ota.ccnubox.muxixyz.com"); err == nil {
		t.Fatal("没拿到 certID 时必须报错，否则后面会用空 certID 去绑域名")
	}
}
