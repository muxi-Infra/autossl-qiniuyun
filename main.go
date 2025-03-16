package main

import (
	"github.com/gin-gonic/gin"
	"github.com/muxi-Infra/autossl-qiniuyun/config"
	"github.com/muxi-Infra/autossl-qiniuyun/cron"
)

func main() {
	config.InitViper("./config")
	app := InitApp()
	app.Serve()
	return
}

type App struct {
	corn cron.Corn
	g    *gin.Engine
}

func NewApp(cron cron.Corn, g *gin.Engine) *App {
	return &App{
		corn: cron,
		g:    g,
	}
}

func (app *App) Serve() {
	app.corn.Start()
	app.g.Run(":8080")
}
