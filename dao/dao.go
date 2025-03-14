package dao

import (
	"gorm.io/gorm"
)

// DomainDao 负责 Domain 表的数据库操作
type DomainDao struct {
	db *gorm.DB
}

// NewDomainDAO 创建一个新的 DomainDao 实例
func NewDomainDAO(db *gorm.DB) *DomainDao {
	return &DomainDao{db: db}
}

// GetDomainList 获取所有的 Domain 记录
func (d *DomainDao) GetDomainList() ([]Domain, error) {
	var domainList []Domain
	err := d.db.Find(&domainList).Error
	return domainList, err
}

// SaveDomainList 批量保存 Domain 数据
func (d *DomainDao) SaveDomainList(domainList []Domain) error {
	return d.db.Save(&domainList).Error
}
