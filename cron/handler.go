package cron

import (
	"context"
	"fmt"
	"github.com/muxi-Infra/autossl-qiniuyun/dao"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/email"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/qiniu"
	"github.com/muxi-Infra/autossl-qiniuyun/pkg/ssl"
	"gorm.io/gorm"
	"time"
)

var (
	qiniuClient *qiniu.QiniuClient
	sslDAO      *dao.SSLDao
	cmClient    *ssl.CertMagicClient
	emailClient *email.EmailClient
	strangerMap = NewStrategyMap()
	receiver    string
	now         int64
)

const (
	CheckLocalErrCode int = iota
	CheckQiniuCertErrCode
	ObtainCertErrCode
	UploadCertErrCode
	ForceHTTPSErrCode
	RemoveOldCertErrCode
	StartAll = 0 //这里和第一个错误是一致的code
)

//1. 如果这个父域名证书找不到（本地和云端任何一个地方找不到）或者过期了就要申请并存储。保证存在可用的父域名证书

// 2. 检查这个证书在本地是否已经存储了当前处理的域名,如果未存储则在七牛云上强制启用，并在本地进行存储

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

// 1. 检查本地是否存在证书

type CheckLocalCertHandler struct {
	BaseHandler
}

func (h *CheckLocalCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	s, err := sslDAO.GetSSLByName(domain.FatherDomain)
	switch err {
	case nil:
		domain.CertId = s.CertID
	case gorm.ErrRecordNotFound:
		//本地不存在该父域名的证书,则不进行添加,下游逻辑会进行处理
		domain.CertId = ""
	default:
		return CheckLocalErrCode, err
	}
	return h.HandleNext(ctx, domain)
}

// 2. 检查云端仓库是否存在证书
type CheckQiniuCertHandler struct {
	BaseHandler
}

func (h *CheckQiniuCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	if domain.CertId != "" {
		//如果id无法从七牛云上获取证书,说明证书不存在,将证书id设置为空
		resp, err := qiniuClient.GETSSLCertById(domain.CertId)
		if err != nil {
			//删除当前的本地证书,并将证书状态设置为无证书
			err := sslDAO.DeleteSSL(domain.CertId)
			if err != nil {
				return CheckQiniuCertErrCode, err
			}
			domain.CertId = ""
		} else {
			//检查是否已经过期,如果过期需要删除当前的本地和云端的证书
			if checkIfPass(resp.NotAfter) {
				//设置证书为老证书,清除证书
				domain.OldCertId = domain.CertId
				domain.CertId = ""
			}
		}
	}
	return h.HandleNext(ctx, domain)
}

// 3. 申请证书
type ObtainCertHandler struct {
	BaseHandler
}

func (h *ObtainCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	//如果无证书
	if domain.CertId == "" {
		//尝试获取证书
		certPEM, keyPEM, err := cmClient.ObtainCert(ctx, "*."+domain.FatherDomain)
		if err != nil {
			return ObtainCertErrCode, err
		}
		domain.CertPEM = certPEM
		domain.KeyPEM = keyPEM
	}

	return h.HandleNext(ctx, domain)
}

// 4. 上传证书
type UploadCertHandler struct {
	BaseHandler
}

func (h *UploadCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {

	certId, err := qiniuClient.UPSSLCert(domain.KeyPEM, domain.CertPEM, domain.FatherDomain)
	if err != nil {
		return UploadCertErrCode, err
	}

	domain.CertId = certId.CertID
	return h.HandleNext(ctx, domain)
}

// 6. 强制开启 HTTPS并将成功的部分存到本地,失败的保留
type ForceHTTPSHandler struct {
	BaseHandler
}

func (h *ForceHTTPSHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	//强制开启https并将失败的加入到失败列表里面
	var fails []string
	var success []string
	for _, d := range domain.Domains {
		//防止七牛云限流
		time.Sleep(3 * time.Second)

		err = qiniuClient.ForceHTTPS(d, domain.CertId)
		if err != nil {
			fails = append(fails, d)
			continue
		}
		success = append(success, d)

	}

	// 获取已存在的 SSL 证书
	_, domains, err := sslDAO.GetDomains(domain.FatherDomain)
	switch err {
	case nil:
		//如果能够找到证书不进行任何处理,因为需要再任务结束后再重新保存证书
		// 更新证书与域名
		err = sslDAO.UpdateSSL(domain.CertId, append(domains, success...))
		if err != nil {
			return ForceHTTPSErrCode, err
		}
	case gorm.ErrRecordNotFound:
		// 如果查不到证书，创建新证书
		err := sslDAO.CreateSSL(domain.CertId, domain.CertId, domain.KeyPEM, domain.Domains)
		if err != nil {
			return ForceHTTPSErrCode, err
		}
	default:
		// 遇到其他未知错误
		return ForceHTTPSErrCode, fmt.Errorf("unexpected error: %w", err)
	}

	//将域名列表更新为失败域名
	domain.Domains = fails

	return h.HandleNext(ctx, domain)
}

// 7. 移除远程久旧证书
type RemoveOldCertHandler struct {
	BaseHandler
}

func (h *RemoveOldCertHandler) Handle(ctx context.Context, domain *DomainWithCert) (code int, err error) {
	if domain.OldCertId != "" {
		err := qiniuClient.RemoveSSLCert(domain.OldCertId)
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
		CheckLocalErrCode: buildHandlerChain(
			&CheckLocalCertHandler{},
			&CheckQiniuCertHandler{},
			&ObtainCertHandler{},
			&UploadCertHandler{},

			&ForceHTTPSHandler{},
			&RemoveOldCertHandler{},
		),
		CheckQiniuCertErrCode: buildHandlerChain(
			&CheckQiniuCertHandler{},
			&ObtainCertHandler{},
			&UploadCertHandler{},

			&ForceHTTPSHandler{},
			&RemoveOldCertHandler{},
		),
		ObtainCertErrCode: buildHandlerChain(
			&ObtainCertHandler{},
			&UploadCertHandler{},

			&ForceHTTPSHandler{},
			&RemoveOldCertHandler{},
		),
		UploadCertErrCode: buildHandlerChain(
			&UploadCertHandler{},

			&ForceHTTPSHandler{},
			&RemoveOldCertHandler{},
		),
		ForceHTTPSErrCode: buildHandlerChain(
			&ForceHTTPSHandler{},
			&RemoveOldCertHandler{},
		),
		RemoveOldCertErrCode: buildHandlerChain(
			&RemoveOldCertHandler{},
		),
	}
}

func checkIfPass(t int64) bool {
	return now-t < ExpirationThreshold*SecondsPerDay
}

//	TODO 3.14计划
//	1. 完成上传功能的重构
//  2. 完成热更新功能的接口,目前打算直接提供一个GET和一个PUT接口实现最轻量化的更新

//  TODO 3.15计划
//  1. 完成所有开发任务
//  2. 在生产环境进行测试
//  3. 编写README文档

// TODO 后续迭代计划
// 先看看有没有需求吧
// 可以作为自己的一个重要开源项目和进入devops领域的一个跳板
// 支持更多平台?
// 支持可视化?
