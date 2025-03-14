package router

import "github.com/gin-gonic/gin"

func InitRouter() *gin.Engine {
	g := gin.Default()
	api := g.Group("/api/v1")

	// 提供PUT方法进行外部热更新配置
	api.PUT()

	// 添加禁止自动申请黑名单, 注意做域名检查
	api.POST()

	// 从禁止自动申请黑名单中移除
	api.DELETE()

	// 查询当前的黑名单
	api.GET()

	return g
}
