package dao

import "gorm.io/gorm"

type Domain struct {
	gorm.Model
	name string
}
