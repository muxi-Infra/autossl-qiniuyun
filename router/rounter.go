package router

import (
	"github.com/gin-gonic/gin"
	"github.com/muxi-Infra/autossl-qiniuyun/controller"
	"github.com/muxi-Infra/autossl-qiniuyun/service"
)

func InitRouter(s *service.Service) *gin.Engine {
	g := gin.Default()
	api := g.Group("/api/v1")
	conf := controller.NewController(s)
	conf.RegisterRoutes(api)
	return g
}
