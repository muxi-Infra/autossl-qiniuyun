package email

import (
	"fmt"
	"github.com/jordan-wright/email"
	"net/smtp"
)

// EmailClient 结构体
type EmailClient struct {
	SMTPHost string // SMTP 服务器地址
	SMTPPort string // SMTP 端口（25、465（SSL）、587（TLS））
	SMTPUser string // 邮箱用户名
	SMTPPass string // 邮箱密码
	Sender   string // 发件人
}

// NewEmailClient 创建邮件客户端
func NewEmailClient(
	userName,
	password,
	sender,
	smtpHost,
	smtpPort string) *EmailClient {
	return &EmailClient{
		SMTPHost: smtpHost,
		SMTPPort: smtpPort,
		SMTPUser: userName,
		SMTPPass: password,
		Sender:   sender,
	}
}

// SendEmail 发送邮件
func (c *EmailClient) SendEmail(to []string, subject, text, html string, attachments []string) error {
	e := email.NewEmail()

	// 发件人
	e.From = fmt.Sprintf("%s <%s>", c.Sender, c.SMTPUser)

	// 收件人
	e.To = to

	// 主题
	e.Subject = subject

	// 纯文本内容
	e.Text = []byte(text)

	// HTML 内容
	e.HTML = []byte(html)

	// 添加附件
	for _, filePath := range attachments {
		if _, err := e.AttachFile(filePath); err != nil {
			return fmt.Errorf("附件添加失败: %v", err)
		}
	}

	// SMTP 认证
	auth := smtp.PlainAuth("", c.SMTPUser, c.SMTPPass, c.SMTPHost)

	// 发送邮件
	err := e.Send(fmt.Sprintf("%s:%s", c.SMTPHost, c.SMTPPort), auth)
	if err != nil {
		return fmt.Errorf("邮件发送失败: %v", err)
	}

	return nil
}
