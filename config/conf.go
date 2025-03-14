package config

import (
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	"log"
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
	Changed bool // 记录是否发生变更
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

// GetEmailConf 获取 Email 配置
func GetEmailConf() EmailConf {
	mu.Lock()
	defer mu.Unlock()
	return EmailConfig
}

// GetQiniuConf 获取 Qiniu 配置
func GetQiniuConf() QiniuConf {
	mu.Lock()
	defer mu.Unlock()
	return QiniuConfig
}

// GetSSLConf 获取 SSL 配置
func GetSSLConf() SSLConf {
	mu.Lock()
	defer mu.Unlock()
	return SSLConfig
}

// SetEmailConf 修改 Email 配置
func SetEmailConf(newConf EmailConf) error {
	mu.Lock()
	defer mu.Unlock()
	EmailConfig = newConf
	viper.Set("email", newConf) // 更新 Viper 中的值
	return viper.WriteConfig()  // 写回文件
}

// SetQiniuConf 修改 Qiniu 配置
func SetQiniuConf(newConf QiniuConf) error {
	mu.Lock()
	defer mu.Unlock()

	QiniuConfig = newConf
	viper.Set("qiniu", newConf) // 更新 Viper 中的值
	return viper.WriteConfig()  // 写回文件
}

// SetSSLConf 修改 SSL 配置
func SetSSLConf(newConf SSLConf) error {
	mu.Lock()
	defer mu.Unlock()
	SSLConfig = newConf
	viper.Set("ssl", newConf)
	return viper.WriteConfig()
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
