package dao

import (
	"gorm.io/gorm"
)

// SSL 证书表
type SSL struct {
	gorm.Model
	DomainName string `gorm:"type:varchar(255);not null"`
	CertID     string `gorm:"unique;not null"` // 证书 ID
	CertPEM    string
	KeyPEM     string
	Domains    []Domain `gorm:"foreignKey:SSLID"` // 关联 Domain
}

// Domain 域名表
type Domain struct {
	gorm.Model
	Name  string `gorm:"unique;not null"` // 域名
	SSLID uint   // 关联的 SSL 证书 ID
}
