//go:generate wire
//go:build wireinject

package main

import (
	"github.com/google/wire"
	"github.com/muxi-Infra/autossl-qiniuyun/controller"
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
	"github.com/muxi-Infra/autossl-qiniuyun/router"
	"github.com/muxi-Infra/autossl-qiniuyun/service"
)

// wireSet 定义所有依赖
var wireSet = wire.NewSet(
	service.NewService,
	controller.NewController,
	cron.NewQiniuSSL,
	cron.NewCorn,
	router.InitRouter,
	NewApp,
)

func InitApp() *App {
	wire.Build(
		wireSet,
	)
	return &App{}
}
