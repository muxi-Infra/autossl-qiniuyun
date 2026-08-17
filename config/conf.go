package config

import (
	"bytes"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/nacos-group/nacos-sdk-go/clients"
	"github.com/nacos-group/nacos-sdk-go/common/constant"
	"github.com/nacos-group/nacos-sdk-go/vo"
	"github.com/spf13/viper"
)

type EmailConf struct {
	UserName string `yaml:"username"`
	Password string `yaml:"password"`
	Sender   string `yaml:"sender"`
	Receiver string `yaml:"receiver"`
	SmtpPort string `yaml:"smtpPort"`
	SmtpHost string `yaml:"smtpHost"`
}

type QiniuConf struct {
	AccessKey string `yaml:"accessKey"`
	SecretKey string `yaml:"secretKey"`
}

type SSLConf struct {
	Email    string        `yaml:"email"`
	Duration time.Duration `yaml:"duration"`
	SSLPath  string        `yaml:"sslPath"`
	Aliyun   struct {
		AccessKeyID     string `yaml:"accessKeyID"`
		AccessKeySecret string `yaml:"accessKeySecret"`
	} `yaml:"aliyun"`
	DB string `yaml:"db"`
	// ForceHTTPS 开启后七牛云会把 http 请求 301 到 https，默认关闭
	ForceHTTPS bool `yaml:"forceHTTPS"`
	// HTTP2 是否开启 http2，默认关闭
	HTTP2 bool `yaml:"http2"`
}

type Conf struct {
	SSL   SSLConf   `yaml:"ssl"`
	Qiniu QiniuConf `yaml:"qiniu"`
	Email EmailConf `yaml:"email"`
}

// 主入口：从 Nacos 拉取配置（一次性）
func GetConfig() (*Conf, error) {

	//从nacos获取
	content, err := getConfigFromNacos()
	if err != nil {
		log.Println(err)

		localPath := "./config/config.yaml"
		fileContent, err := os.ReadFile(localPath)
		if err != nil {
			// 如果本地文件也读取失败，则彻底失败
			log.Fatalf("无法读取本地配置文件 %s，且 Nacos 配置获取失败: %v", localPath, err)
			return nil, err
		}
		content = string(fileContent)
	}

	v := viper.New()
	v.SetConfigType("yaml")

	if err := v.ReadConfig(bytes.NewBufferString(content)); err != nil {
		log.Fatal("配置解析失败:", err)
		return nil, err
	}

	var conf Conf
	err = v.Unmarshal(&conf)
	if err != nil {
		log.Fatal(err)
		return nil, err
	}

	return &conf, nil
}
func getConfigFromNacos() (string, error) {
	server, port, namespace, user, pass, group, dataId := parseNacosDSN()

	serverConfigs := []constant.ServerConfig{
		{
			IpAddr: server,
			Port:   port,
			Scheme: "http",
		},
	}

	clientConfig := constant.ClientConfig{
		NamespaceId:         namespace,
		Username:            user,
		Password:            pass,
		TimeoutMs:           5000,
		NotLoadCacheAtStart: true,
		CacheDir:            "./data/configCache",
	}

	configClient, err := clients.CreateConfigClient(map[string]interface{}{
		"serverConfigs": serverConfigs,
		"clientConfig":  clientConfig,
	})
	if err != nil {
		log.Fatal("初始化失败:", err)
	}

	content, err := configClient.GetConfig(vo.ConfigParam{
		DataId: dataId,
		Group:  group,
	})
	if err != nil {
		log.Fatal("拉取配置失败:", err)
	}
	return content, nil
}

// DSN 示例： localhost:8848?namespace=default&username=nacos&password=1234&group=QA&dataId=my-service
func parseNacosDSN() (server string, port uint64, ns, user, pass, group, dataId string) {
	dsn := os.Getenv("NACOSDSN")
	if dsn == "" {
		log.Fatal("环境变量 NACOSDSN 未设置")
	}

	parts := strings.SplitN(dsn, "?", 2)
	host := parts[0]
	params := url.Values{}

	if len(parts) == 2 {
		params, _ = url.ParseQuery(parts[1])
	}

	hostParts := strings.Split(host, ":")
	server = hostParts[0]
	if len(hostParts) > 1 {
		p, _ := strconv.Atoi(hostParts[1])
		port = uint64(p)
	} else {
		port = 8848
	}

	ns = params.Get("namespace")
	if ns == "" {
		ns = "public"
	}

	user = params.Get("username")
	pass = params.Get("password")
	group = params.Get("group")
	dataId = params.Get("dataId")
	return
}
