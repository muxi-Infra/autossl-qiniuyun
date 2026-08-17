package dao

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// SSLDao 负责 SSL 表的数据库操作
type SSLDao struct {
	db *gorm.DB
}

// NewSSLDao 创建一个新的 SSLDao 实例
func NewSSLDao(path string) (*SSLDao, error) {
	// 自动创建父级目录
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create db directory failed: %w", err)
	}

	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	// 自动迁移表结构
	if err := db.AutoMigrate(&SSL{}, &Domain{}); err != nil {
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return &SSLDao{db: db}, nil
}

// GetSSLByID 通过 certId 获取 SSL 证书
func (dao *SSLDao) GetSSLByID(certId string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("cert_id= ?", certId).First(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

// GetSSLByID 通过 certId 获取 SSL 证书
func (dao *SSLDao) GetSSLByName(name string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("domain_name= ?", name).Find(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

func (dao *SSLDao) GetSSLS() (*[]SSL, error) {
	var ssl []SSL
	err := dao.db.Preload("Domains").Find(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

// GetSSLByCertID 通过 CertID 获取 SSL 证书
func (dao *SSLDao) GetSSLByCertID(certID string) (*SSL, error) {
	var ssl SSL
	err := dao.db.Preload("Domains").Where("cert_id = ?", certID).First(&ssl).Error
	if err != nil {
		return nil, err
	}
	return &ssl, nil
}

func (dao *SSLDao) GetDomains(domainName string) (int64, []string, error) {
	var ssl SSL
	var domainNames []string

	// 查询 SSL 记录
	if err := dao.db.Preload("Domains").Where("domain_name = ?", domainName).First(&ssl).Error; err != nil {
		return 0, nil, err
	}

	// 提取所有域名
	for _, domain := range ssl.Domains {
		domainNames = append(domainNames, domain.Name)
	}

	return ssl.NotAfter.Unix(), domainNames, nil
}

// SaveSSL 覆盖式保存证书及其绑定的域名。
// Domain.Name 是全局唯一键，域名从旧证书迁移到新证书时必须先清掉历史绑定，否则 Create 会撞唯一键。
func (dao *SSLDao) SaveSSL(ssl *SSL) error {
	return dao.db.Transaction(func(tx *gorm.DB) error {
		var old SSL
		if err := tx.Unscoped().Where("cert_id = ?", ssl.CertID).Find(&old).Error; err != nil {
			return err
		}
		if old.ID != 0 {
			if err := tx.Unscoped().Where("ssl_id = ?", old.ID).Delete(&Domain{}).Error; err != nil {
				return err
			}
			if err := tx.Unscoped().Delete(&old).Error; err != nil {
				return err
			}
		}

		// 清理这些域名挂在其它证书下的历史记录
		if names := domainNames(ssl.Domains); len(names) > 0 {
			if err := tx.Unscoped().Where("name IN ?", names).Delete(&Domain{}).Error; err != nil {
				return err
			}
		}

		// 主键与时间戳交给 gorm 生成，避免带着旧 ID 显式插入
		ssl.ID = 0
		ssl.CreatedAt = time.Time{}
		ssl.UpdatedAt = time.Time{}
		for i := range ssl.Domains {
			ssl.Domains[i].ID = 0
			ssl.Domains[i].SSLID = 0
			ssl.Domains[i].CreatedAt = time.Time{}
			ssl.Domains[i].UpdatedAt = time.Time{}
		}

		return tx.Create(ssl).Error
	})
}

func domainNames(domains []Domain) []string {
	names := make([]string, 0, len(domains))
	for _, d := range domains {
		names = append(names, d.Name)
	}
	return names
}

// DeleteSSL 硬删除 SSL 证书及关联域名
func (dao *SSLDao) DeleteSSL(certID string) error {
	var ssl SSL
	if err := dao.db.Unscoped().Where("cert_id = ?", certID).Find(&ssl).Error; err != nil {
		return err
	}
	if ssl.ID == 0 {
		return nil
	}

	// 直接硬删除关联的域名
	if err := dao.db.Unscoped().Where("ssl_id = ?", ssl.ID).Delete(&Domain{}).Error; err != nil {
		return err
	}

	// 直接硬删除 SSL 记录
	return dao.db.Unscoped().Delete(&ssl).Error
}
