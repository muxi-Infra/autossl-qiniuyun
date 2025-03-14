package main

import (
	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
)

func main() {
	config.InitViper("./config")
	q := cron.NewQiniuSSL()
	q.Start()
	return
}

//type App struct {
//	corn cron.Corn
//	g    *gin.Engine
//}
//
//func InitApp(cron cron.Corn, g *gin.Engine) *App {
//	return &App{
//		corn: cron,
//		g:    g,
//	}
//}
//
//func (app *App) Serve() {
//	//
//	app.corn.Start()
//
//	//app.g.Run(":8080")
//}

//func Cron() {
//
//}
//
//func getDomains() {
//
//	//qvs.NewManager()
//
//}

// 定时获取七牛云的所有域名列表

// 查询本地证书,获取需要申请证书的域名

// 如果30天内即将过期或者本地不存在该域名则添加到列表并自动申领

// 申领失败的域名添加到域名申请失败列表

// 尝试更换平台申请域名证书

// 如果所有平台均失败则进行报警

// 自动上传证书到七牛云

// 上传失败的证书添加到证书上传失败列表

// 当前失败的域名进入限流域名列表，半小时后进行重试，如果半小时后依旧失败则进行报警
