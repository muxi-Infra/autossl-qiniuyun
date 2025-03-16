package config

import (
	"bytes"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"reflect"
	"sync"
	"time"
)

// 定义全局配置变量
var (
	EmailConfig EmailConf
	QiniuConfig QiniuConf
	SSLConfig   SSLConf
	mu          sync.Mutex // 保护写操作的互斥锁
	initialized bool       // 用来标识是否为初次启动
)

type EmailConf struct {
	UserName string `yaml:"username"`
	Password string `yaml:"password"`
	Sender   string `yaml:"sender"`
	Receiver string `yaml:"receiver"`
	SmtpPort string `yaml:"smtpPort"`
	SmtpHost string `yaml:"smtpHost"`
	Changed  bool   // 记录是否发生变更
}

type QiniuConf struct {
	AccessKey string `yaml:"accessKey"`
	SecretKey string `yaml:"secretKey"`
	Changed   bool   // 记录是否发生变更
}

type SSLConf struct {
	Email    string        `yaml:"email"`
	Duration time.Duration `yaml:"duration"`
	SSLPath  string        `yaml:"sslPath"`
	Aliyun   struct {
		AccessKeyID     string `yaml:"accessKeyID"`
		AccessKeySecret string `yaml:"accessKeySecret"`
	} `yaml:"aliyun"`
	DB      string `yaml:"db"`
	Changed bool   // 记录是否发生变更
}

type CronConf struct {
	EmailConf
	QiniuConf
	SSLConf
}

// InitViper 初始化 Viper 并监听配置文件变化
func InitViper(path string) {
	viper.AddConfigPath(path)
	viper.SetConfigName("config")
	viper.SetConfigType("yaml") // 确保 Viper 识别 YAML 格式

	// 读取配置文件
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal("读取配置文件失败:", err.Error())
	}

	// 加载初始配置
	ReloadConfig()

	// 监听配置文件变化
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("配置文件发生变化，重新加载...")
		ReloadConfig()
	})
}

// CheckAndUpdate 统一检查配置变更，排除 Changed 字段的影响
func CheckAndUpdate(oldValue, newValue interface{}, changed *bool) {
	// 使用 reflect 包来比较两个结构体的值是否不同，排除 Changed 字段
	if !reflect.DeepEqual(removeChangedField(oldValue), removeChangedField(newValue)) {
		*changed = true
		reflect.ValueOf(oldValue).Elem().Set(reflect.ValueOf(newValue))
	} else {
		*changed = false
	}
}

// removeChangedField 从结构体中移除 Changed 字段，以避免其影响
func removeChangedField(value interface{}) interface{} {
	val := reflect.ValueOf(value).Elem()
	if val.Kind() != reflect.Struct {
		return value
	}

	// 遍历结构体字段，忽略 Changed 字段
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		if val.Type().Field(i).Name == "Changed" {
			// 将 Changed 字段的值置为零值，避免其影响比较
			field.Set(reflect.Zero(field.Type()))
		}
	}

	return value
}

// ReloadConfig 重新加载配置到结构体
func ReloadConfig() {
	mu.Lock()
	defer mu.Unlock()

	var newEmailConf EmailConf
	var newQiniuConf QiniuConf
	var newSSLConf SSLConf

	if err := viper.UnmarshalKey("email", &newEmailConf); err != nil {
		log.Println("解析 Email 配置失败:", err)
		return
	}

	if err := viper.UnmarshalKey("qiniu", &newQiniuConf); err != nil {
		log.Println("解析 Qiniu 配置失败:", err)
		return
	}

	if err := viper.UnmarshalKey("ssl", &newSSLConf); err != nil {
		log.Println("解析 SSL 配置失败:", err)
		return
	}

	// 如果是初次启动，则直接赋值并初始化 Changed 为 false
	if !initialized {
		EmailConfig = newEmailConf
		EmailConfig.Changed = true
		QiniuConfig = newQiniuConf
		QiniuConfig.Changed = true
		SSLConfig = newSSLConf
		SSLConfig.Changed = true
		initialized = true
	} else {
		// 检查变更
		CheckAndUpdate(&EmailConfig, newEmailConf, &EmailConfig.Changed)
		CheckAndUpdate(&QiniuConfig, newQiniuConf, &QiniuConfig.Changed)
		CheckAndUpdate(&SSLConfig, newSSLConf, &SSLConfig.Changed)
	}
}

// WriteConfigToFile 将配置写入 YAML 文件
func WriteConfigToFile(cronConf *CronConf) error {
	mu.Lock()
	defer mu.Unlock()

	// 将 CronConf 结构体转换为 YAML
	data, err := yaml.Marshal(cronConf)
	if err != nil {
		log.Println("序列化 YAML 失败:", err)
		return err
	}

	// 获取配置文件路径
	configPath := viper.ConfigFileUsed()

	// 写入 YAML 文件
	err = os.WriteFile(configPath, data, 0644)
	if err != nil {
		log.Println("写入配置文件失败:", err)
		return err
	}

	// 让 Viper 重新加载配置
	err = viper.ReadInConfig()
	if err != nil {
		log.Println("重新加载 Viper 配置失败:", err)
		return err
	}

	// 重新加载全局配置变量
	ReloadConfig()

	log.Println("配置文件更新成功！")
	return nil
}

// LoadConfigFromYAML 解析 YAML 字符串到结构体
func LoadConfigFromYAML(yamlData string) (*CronConf, error) {
	var newConfig CronConf

	decoder := yaml.NewDecoder(bytes.NewReader([]byte(yamlData)))
	err := decoder.Decode(&newConfig)
	if err != nil {
		log.Println("解析 YAML 失败:", err)
		return nil, err
	}

	return &newConfig, nil
}

// GetAllConfigsAsYAML 获取所有配置并转换为 YAML 字符串
func GetAllConfigsAsYAML() (string, error) {
	mu.Lock()
	defer mu.Unlock()

	config := GetCronConfig()

	// 序列化成 YAML 格式
	data, err := yaml.Marshal(config)
	if err != nil {
		log.Println("序列化 YAML 失败:", err)
		return "", err
	}

	return string(data), nil
}

// GetCronConfig 获取 Cron 配置
func GetCronConfig() *CronConf {
	mu.Lock()
	defer mu.Unlock()
	return &CronConf{
		EmailConf: EmailConfig,
		QiniuConf: QiniuConfig,
		SSLConf:   SSLConfig,
	}
}
