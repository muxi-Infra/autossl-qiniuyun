package controller

import (
	"github.com/gin-gonic/gin"
	"github.com/muxi-Infra/autossl-qiniuyun/api/request"
	"github.com/muxi-Infra/autossl-qiniuyun/api/response"
	"net/http"
)

// IService 定义 Service 层接口
type IService interface {
	GetAllConfigsAsYAML() (string, error)
	OverwriteConfigsFromYAML(yamlConfig string) error
}

// Controller 结构体
type Controller struct {
	service IService
}

// NewController 创建 Controller 实例
func NewController(svc IService) *Controller {
	return &Controller{
		service: svc,
	}
}

// RegisterRoutes 注册路由
func (c *Controller) RegisterRoutes(router *gin.RouterGroup) {
	api := router.Group("/config")
	{
		api.GET("/yaml", c.GetAllConfigsAsYAML)
		api.PUT("/yaml", c.OverwriteConfigsFromYAML)
	}
}

// GetAllConfigsAsYAML 获取当前配置的 YAML 内容
// @Summary 获取当前 YAML 配置
// @Description 返回整个 YAML 配置文件内容
// @Tags 配置管理
// @Accept json
// @Produce json
// @Success 200 {object} response.Resp "返回 YAML 格式的配置内容"
// @Failure 500 {object} response.Resp{data=response.GetConfResp} "服务器错误"
// @Router /config/yaml [get]
func (c *Controller) GetAllConfigsAsYAML(ctx *gin.Context) {
	yamlConfig, err := c.service.GetAllConfigsAsYAML()
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, response.Resp{
			Code:    50001,
			Message: "获取配置失败!",
		})
		return
	}
	ctx.JSON(http.StatusOK, response.Resp{
		Code:    0,
		Message: "获取配置成功!",
		Data:    response.GetConfResp{Conf: yamlConfig},
	})
}

// OverwriteConfigsFromYAML 覆盖 YAML 配置
// @Summary 更新 YAML 配置
// @Description 接收 JSON 格式的 YAML 配置内容并覆盖当前配置
// @Tags 配置管理
// @Accept json
// @Produce json
// @Param request body request.PUTConfReq true "更新配置"
// @Success 200 {object} response.Resp "更新成功"
// @Failure 400 {object} response.Resp "请求格式错误"
// @Failure 500 {object} response.Resp "服务器错误"
// @Router /config/yaml [put]
func (c *Controller) OverwriteConfigsFromYAML(ctx *gin.Context) {
	// 定义 JSON 请求体结构
	var req request.PUTConfReq

	// 解析 JSON 请求体
	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, response.Resp{
			Code:    40001,
			Message: "请求格式错误!",
		})
		return
	}

	// 调用 Service 层进行配置覆盖
	err := c.service.OverwriteConfigsFromYAML(req.Conf)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "更新配置失败"})
		return
	}

	ctx.JSON(http.StatusOK, response.Resp{
		Code:    0,
		Message: "更新配置成功!",
	})
}
