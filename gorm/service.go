package gorm

import (
	"errors"

	controller "github.com/Brickchain/go-controller.v2"
	"github.com/jinzhu/gorm"
)

type gormBindingService struct {
	db             *gorm.DB
	postBindFunc   func(controller.Binding)
	postUnbindFunc func(controller.Binding)
}

func New(db *gorm.DB) controller.BindingService {
	g := &gormBindingService{
		db: db,
	}

	db.AutoMigrate(&gormBinding{})

	return g
}

func (g *gormBindingService) SetPostBind(f func(controller.Binding)) {
	g.postBindFunc = f
}

func (g *gormBindingService) PostBind() func(controller.Binding) {
	return g.postBindFunc
}

func (g *gormBindingService) SetPostUnbind(f func(controller.Binding)) {
	g.postUnbindFunc = f
}

func (g *gormBindingService) PostUnbind() func(controller.Binding) {
	return g.postUnbindFunc
}

func (g *gormBindingService) New(id string) (controller.Binding, error) {
	if b, err := g.Get(id); err == nil {
		return b, errors.New("Binding already exists")
	}

	b := newGormBinding(g.db, id, g.postBindFunc, g.postUnbindFunc)
	err := g.db.Save(b).Error

	return b, err
}

func (g *gormBindingService) Get(id string) (controller.Binding, error) {
	b := &gormBinding{}
	err := g.db.Where("id = ?", id).First(&b).Error

	b.db = g.db

	return b, err
}

func (g *gormBindingService) Delete(id string) error {
	_, err := g.Get(id)
	if err != nil {
		return err
	}
	return g.db.Delete(&gormBinding{}, "id = ?", id).Error
}
