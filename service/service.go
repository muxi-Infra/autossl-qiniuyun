package service

import (
	"github.com/muxi-Infra/autossl-qiniuyun/config" // 替换为你的实际包路径
)

// Service 结构体
type Service struct{}

// NewService 创建 Service 实例
func NewService() *Service {
	return &Service{}
}

// GetAllConfigsAsYAML 获取所有配置（返回 YAML 字符串）
func (s *Service) GetAllConfigsAsYAML() (string, error) {
	return config.GetAllConfigsAsYAML()
}

// OverwriteConfigsFromYAML 覆盖配置（接收 YAML 字符串）
func (s *Service) OverwriteConfigsFromYAML(yamlData string) error {
	newConfig, err := config.LoadConfigFromYAML(yamlData)
	if err != nil {
		return err
	}
	return config.WriteConfigToFile(newConfig)
}
