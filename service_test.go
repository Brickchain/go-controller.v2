package controller_test

import (
	"os"
	"testing"

	controller "github.com/Brickchain/go-controller.v2"
	"github.com/Brickchain/go-document.v2"

	gormcontroller "github.com/Brickchain/go-controller.v2/gorm"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
)

type service struct {
	Name   string
	Create func(*testing.T) controller.BindingService
}

var services []*service

func TestMain(m *testing.M) {
	services = make([]*service, 0)

	services = append(services, &service{
		Name: "Mock",
		Create: func(t *testing.T) controller.BindingService {
			return controller.NewMockBindingService()
		},
	})

	services = append(services, &service{
		Name: "Gorm",
		Create: func(t *testing.T) controller.BindingService {
			db, err := gorm.Open("sqlite3", ":memory:")
			if err != nil {
				t.Fatal(err)
			}

			return gormcontroller.New(db)
		},
	})

	os.Exit(m.Run())
}

func Test_BindingService_New(t *testing.T) {
	type test struct {
		name    string
		svc     controller.BindingService
		prepare func(*testing.T, test)
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name:    "New",
			id:      "test",
			wantErr: false,
		},
		{
			name: "Existing",
			prepare: func(t *testing.T, tt test) {
				tt.svc.New(tt.id)
			},
			id:      "test",
			wantErr: true,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, tt)
					}
					got, err := tt.svc.New(tt.id)
					if (err != nil) != tt.wantErr {
						t.Errorf("BindingService.New() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					if got.ID() != tt.id {
						t.Errorf("BindingService.New() = %v, want %v", got.ID(), tt.id)
					}
				})
			}
		})
	}
}

func Test_BindingService_Get(t *testing.T) {
	type test struct {
		name    string
		svc     controller.BindingService
		prepare func(*testing.T, test)
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name:    "Dont_Exist",
			id:      "test",
			wantErr: true,
		},
		{
			name: "Existing",
			prepare: func(t *testing.T, tt test) {
				tt.svc.New(tt.id)
			},
			id:      "test",
			wantErr: false,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, tt)
					}
					got, err := tt.svc.Get(tt.id)
					if (err != nil) != tt.wantErr {
						t.Errorf("BindingService.Get() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
					if !tt.wantErr && got.ID() != tt.id {
						t.Errorf("BindingService.Get() = %v, want %v", got.ID(), tt.id)
					}
				})
			}
		})
	}
}

func Test_BindingService_Delete(t *testing.T) {
	type test struct {
		name    string
		svc     controller.BindingService
		prepare func(*testing.T, test)
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name:    "Dont_Exist",
			id:      "test",
			wantErr: true,
		},
		{
			name: "Existing",
			prepare: func(t *testing.T, tt test) {
				tt.svc.New(tt.id)
			},
			id:      "test",
			wantErr: false,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, tt)
					}
					err := tt.svc.Delete(tt.id)
					if (err != nil) != tt.wantErr {
						t.Errorf("BindingService.Delete() error = %v, wantErr %v", err, tt.wantErr)
						return
					}
				})
			}
		})
	}
}

func Test_BindingService_SetPostBind(t *testing.T) {
	type test struct {
		name    string
		svc     controller.BindingService
		f       func(controller.Binding)
		verify  func(*testing.T, test, controller.Binding)
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name: "Update_RequireSetup",
			f: func(binding controller.Binding) {
				binding.SetStatus("true")
			},
			verify: func(t *testing.T, tt test, binding controller.Binding) {
				if binding.Status() != "true" {
					t.Error("Status not true")
				}
			},
			wantErr: false,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					tt.svc.SetPostBind(tt.f)
					binding, _ := tt.svc.New("test")
					if err := binding.Bind(&document.ControllerBinding{}); err != nil {
						t.Error(err)
					}
					if tt.verify != nil {
						tt.verify(t, tt, binding)
					}
				})
			}
		})
	}
}

func Test_BindingService_SetPostUnbind(t *testing.T) {
	type test struct {
		name    string
		svc     controller.BindingService
		f       func(controller.Binding)
		verify  func(*testing.T, test, controller.Binding)
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name: "Update_RequireSetup",
			f: func(binding controller.Binding) {
				binding.SetStatus("true")
			},
			verify: func(t *testing.T, tt test, binding controller.Binding) {
				if binding.Status() != "true" {
					t.Error("Status not true")
				}
			},
			wantErr: false,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					tt.svc.SetPostUnbind(tt.f)
					binding, _ := tt.svc.New("test")
					if err := binding.Bind(&document.ControllerBinding{}); err != nil {
						t.Error(err)
					}
					if err := binding.Unbind(); err != nil {
						t.Error(err)
					}
					if tt.verify != nil {
						tt.verify(t, tt, binding)
					}
				})
			}
		})
	}
}
