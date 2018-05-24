package controller_test

import (
	"testing"

	controller "github.com/Brickchain/go-controller.v2"
	"github.com/Brickchain/go-crypto.v2"
	"github.com/Brickchain/go-document.v2"
	keys "gitlab.brickchain.com/libs/go-keys.v1"
	jose "gopkg.in/square/go-jose.v1"
)

func Test_Binding_ID(t *testing.T) {
	type test struct {
		name string
		id   string
	}
	tests := []test{
		{
			name: "ID",
			id:   "test",
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					g, err := svc.Create(t).New(tt.id)
					if err != nil {
						t.Error(err)
					}
					if got := g.ID(); got != tt.id {
						t.Errorf("Binding.ID() = %v, want %v", got, tt.id)
					}
				})
			}
		})
	}
}

func Test_Binding_Secret(t *testing.T) {
	type test struct {
		name string
		id   string
	}
	tests := []test{
		{
			name: "Secret",
			id:   "test",
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					g, err := svc.Create(t).New(tt.id)
					if err != nil {
						t.Error(err)
					}
					if got := g.Secret(); got == "" {
						t.Errorf("Binding.Secret() = %v, want non-empty value", got)
					}
				})
			}
		})
	}
}

func Test_Binding_GenerateKey(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		ksvc    keys.StoredKeyService
		kek     []byte
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name:    "New",
			ksvc:    keys.NewMockStoredKeyService(),
			kek:     crypto.NewSymmetricKey(jose.A256KW),
			id:      "test",
			wantErr: false,
		},
		{
			name:    "Broken_Key",
			ksvc:    keys.NewMockStoredKeyService(),
			kek:     []byte("broken"),
			id:      "test",
			wantErr: true,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					g, err := svc.Create(t).New(tt.id)
					if err != nil {
						t.Error(err)
					}
					if err := g.GenerateKey(tt.ksvc, tt.kek); (err != nil) != tt.wantErr {
						t.Errorf("Binding.GenerateKey() = %v, wantErr = %v", err, tt.wantErr)
					}
				})
			}
		})
	}
}

func Test_Binding_PublicKey(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		binding controller.Binding
		id      string
		fail    bool
	}
	tests := []test{
		{
			name: "PublicKey",
			prepare: func(t *testing.T, tt *test) {
				if err := tt.binding.GenerateKey(keys.NewMockStoredKeyService(), crypto.NewSymmetricKey(jose.A256KW)); err != nil {
					t.Fatal(err)
				}
			},
			id:   "test",
			fail: false,
		},
		{
			name: "Not_generated",
			id:   "test",
			fail: true,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					var err error
					tt.binding, err = svc.Create(t).New(tt.id)
					if err != nil {
						t.Error(err)
					}
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if got := tt.binding.PublicKey(); (got == nil) != tt.fail {
						t.Errorf("Binding.PublicKey() = %v, fail = %v", got, tt.fail)
					}
				})
			}
		})
	}
}

func Test_Binding_PrivateKey(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		ksvc    keys.StoredKeyService
		kek     []byte
		binding controller.Binding
		id      string
		wantErr bool
	}
	tests := []test{
		{
			name: "New",
			prepare: func(t *testing.T, tt *test) {
				if err := tt.binding.GenerateKey(tt.ksvc, tt.kek); err != nil {
					t.Fatal(err)
				}
			},
			ksvc:    keys.NewMockStoredKeyService(),
			kek:     crypto.NewSymmetricKey(jose.A256KW),
			id:      "test",
			wantErr: false,
		},
		{
			name: "Wrong_Key",
			prepare: func(t *testing.T, tt *test) {
				if err := tt.binding.GenerateKey(tt.ksvc, crypto.NewSymmetricKey(jose.A256KW)); err != nil {
					t.Fatal(err)
				}
			},
			ksvc:    keys.NewMockStoredKeyService(),
			kek:     crypto.NewSymmetricKey(jose.A256KW),
			id:      "test",
			wantErr: true,
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					var err error
					tt.binding, err = svc.Create(t).New(tt.id)
					if err != nil {
						t.Error(err)
					}
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if _, err := tt.binding.PrivateKey(tt.ksvc, tt.kek); (err != nil) != tt.wantErr {
						t.Errorf("Binding.PrivateKey() = %v, wantErr = %v", err, tt.wantErr)
					}
				})
			}
		})
	}
}

func Test_Binding_Bind(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		verify  func(*testing.T, *test)
		svc     controller.BindingService
		binding controller.Binding
	}
	tests := []test{
		{
			name: "New",
			prepare: func(t *testing.T, tt *test) {
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.Bind(&document.ControllerBinding{
					AdminRoles:            []string{"admin"},
					ControllerCertificate: "abc",
					Mandates:              []string{"def"},
					RealmDescriptor:       &document.RealmDescriptor{Name: "example.com"},
				}); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if tt.binding.Certificate() != "abc" {
					t.Fatal("CertificateChain not correct")
				}
				if tt.binding.AdminRoles()[0] != "admin" {
					t.Fatal("AdminRoles not correct")
				}
				if len(tt.binding.Mandates()) < 1 || tt.binding.Mandates()[0] != "def" {
					t.Fatal("Mandates not correct")
				}
				if tt.binding.Realm() == nil || tt.binding.Realm().Name != "example.com" {
					t.Fatal("Realm not correct")
				}
			},
		},
		{
			name: "PostBind",
			prepare: func(t *testing.T, tt *test) {
				f := func(b controller.Binding) {
					b.SetStatus("setup_required")
				}
				tt.svc.SetPostBind(f)
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.Bind(&document.ControllerBinding{}); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if tt.binding.Status() != "setup_required" {
					t.Fatal("Status was not updated by PostBind function")
				}
			},
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if tt.verify != nil {
						tt.verify(t, &tt)
					}
				})
			}
		})
	}
}

func Test_Binding_Unbind(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		verify  func(*testing.T, *test)
		svc     controller.BindingService
		binding controller.Binding
	}
	tests := []test{
		{
			name: "New",
			prepare: func(t *testing.T, tt *test) {
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.Bind(&document.ControllerBinding{
					Mandates: []string{"def"},
				}); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if len(tt.binding.Mandates()) > 0 {
					t.Fatal("Mandates should have been emptied")
				}
			},
		},
		{
			name: "PostBind",
			prepare: func(t *testing.T, tt *test) {
				f := func(b controller.Binding) {
					b.SetStatus("bla")
				}
				tt.svc.SetPostUnbind(f)
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.Bind(&document.ControllerBinding{}); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if tt.binding.Status() != "bla" {
					t.Fatal("Status was not updated by PostUnbind function")
				}
			},
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if err := tt.binding.Unbind(); err != nil {
						t.Fatal(err)
					}
					if tt.verify != nil {
						tt.verify(t, &tt)
					}
				})
			}
		})
	}
}

func Test_Binding_ControllerBinding(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		verify  func(*testing.T, *test)
		svc     controller.BindingService
		binding controller.Binding
	}
	tests := []test{
		{
			name: "New",
			prepare: func(t *testing.T, tt *test) {
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.Bind(&document.ControllerBinding{
					Mandates: []string{"def"},
				}); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if tt.binding.ControllerBinding() == nil || len(tt.binding.ControllerBinding().Mandates) < 1 || tt.binding.ControllerBinding().Mandates[0] != "def" {
					t.Fatal("Setting controller-binding was not correct")
				}
			},
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if tt.verify != nil {
						tt.verify(t, &tt)
					}
				})
			}
		})
	}
}

func Test_Binding_BindEndpoint(t *testing.T) {
	type test struct {
		name    string
		prepare func(*testing.T, *test)
		verify  func(*testing.T, *test)
		svc     controller.BindingService
		binding controller.Binding
	}
	tests := []test{
		{
			name: "New",
			prepare: func(t *testing.T, tt *test) {
				tt.binding, _ = tt.svc.New("test")
				if err := tt.binding.SetBindEndpoint("abc"); err != nil {
					t.Fatal(err)
				}
			},
			verify: func(t *testing.T, tt *test) {
				if tt.binding.BindEndpoint() != "abc" {
					t.Fatalf("BindEndpoint was not correct: %s != abc", tt.binding.BindEndpoint())
				}
			},
		},
	}
	for _, svc := range services {
		t.Run(svc.Name, func(t *testing.T) {
			for _, tt := range tests {
				t.Run(tt.name, func(t *testing.T) {
					tt.svc = svc.Create(t)
					if tt.prepare != nil {
						tt.prepare(t, &tt)
					}
					if tt.verify != nil {
						tt.verify(t, &tt)
					}
				})
			}
		})
	}
}
