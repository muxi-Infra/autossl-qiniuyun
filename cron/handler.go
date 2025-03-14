package cron

import (
	"context"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
)

var (
	qiniuClient *qiniu.QiniuClient
	domainDAO   DomainDAO
	cmClient    *ssl.CertMagicClient
	emailClient *email.EmailClient
	strangerMap = NewStrategyMap()
	receiver    string
)

const (
	ObtainCertErrCode int = iota
	UploadCertErrCode
	ForceHTTPSErrCode
	RemoveOldCertErrCode
	StartAll = 0 //这里和第一个错误是一致的code
)

// 这里包装了一个责任链模式方便进行流程控制与重试
// 责任链处理器接口
type Handler interface {
	SetNext(handler Handler) Handler
	Handle(ctx context.Context, domain *DomainWithCert) (code int, err error)
}

// 基础责任链结构体
type BaseHandler struct {
	next Handler
}

func NewBaseHandler() *BaseHandler {
	return &BaseHandler{}
}

// 设置下一个处理器
func (h *BaseHandler) SetNext(handler Handler) Handler {
	h.next = handler
	return handler
}

// 调用下一个处理器
func (h *BaseHandler) HandleNext(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	if h.next != nil {
		return h.next.Handle(ctx, domain)
	}
	return -1, nil
}

// 1. 申请证书
type ObtainCertHandler struct {
	BaseHandler
}

func (h *ObtainCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	//获取证书
	certPEM, keyPEM, err := cmClient.ObtainCert(ctx, domain.Name)
	if err != nil {
		return ObtainCertErrCode, err
	}

	domain.CertPEM = certPEM
	domain.KeyPEM = keyPEM

	return h.HandleNext(ctx, domain)
}

// 2. 上传证书
type UploadCertHandler struct {
	BaseHandler
}

func (h *UploadCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {

	certId, err := qiniuClient.UPSSLCert(domain.KeyPEM, domain.CertPEM, domain.Name)
	if err != nil {
		return UploadCertErrCode, err
	}

	domain.CertID = certId.CertID
	return h.HandleNext(ctx, domain)
}

// 3. 强制开启 HTTPS
type ForceHTTPSHandler struct {
	BaseHandler
}

func (h *ForceHTTPSHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	err = qiniuClient.ForceHTTPS(domain.Name, domain.CertID)
	if err != nil {
		return ForceHTTPSErrCode, err
	}
	return h.HandleNext(ctx, domain)
}

// 4. 移除旧证书
type RemoveOldCertHandler struct {
	BaseHandler
}

func (h *RemoveOldCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	if domain.OldCertID != "" {
		err := qiniuClient.RemoveSSLCert(domain.OldCertID)
		if err != nil {
			return RemoveOldCertErrCode, err
		}
	}
	return h.HandleNext(ctx, domain)
}

func StartStrategy(code int, domain *DomainWithCert) (int, error) {
	return strangerMap[code].HandleNext(context.Background(), domain)
}

func buildHandlerChain(handlers ...Handler) *BaseHandler {
	if len(handlers) == 0 {
		return nil
	}

	base := NewBaseHandler()
	current := base.SetNext(handlers[0])

	for i := 1; i < len(handlers); i++ {
		current = current.SetNext(handlers[i])
	}

	return base
}

func NewStrategyMap() map[int]*BaseHandler {
	return map[int]*BaseHandler{
		ObtainCertErrCode:    buildHandlerChain(&ObtainCertHandler{}, &UploadCertHandler{}, &ForceHTTPSHandler{}, &RemoveOldCertHandler{}),
		UploadCertErrCode:    buildHandlerChain(&UploadCertHandler{}, &ForceHTTPSHandler{}, &RemoveOldCertHandler{}),
		ForceHTTPSErrCode:    buildHandlerChain(&ForceHTTPSHandler{}, &RemoveOldCertHandler{}),
		RemoveOldCertErrCode: buildHandlerChain(&RemoveOldCertHandler{}),
	}
}
