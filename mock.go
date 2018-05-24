package controller

import (
	"errors"

	"github.com/Brickchain/go-crypto.v2"
	"github.com/Brickchain/go-document.v2"
	keys "gitlab.brickchain.com/libs/go-keys.v1"
	jose "gopkg.in/square/go-jose.v1"
)

type mockBinding struct {
	id             string
	secret         string
	publicKey      *jose.JsonWebKey
	descriptor     document.ControllerDescriptor
	binding        *document.ControllerBinding
	status         string
	bindEndpoint   string
	postBindFunc   func(Binding)
	postUnbindFunc func(Binding)
}

func newMockBinding(id string, postBindFunc, postUnbindFunc func(Binding)) Binding {
	secret, _ := crypto.GenerateRandomString(42)
	return &mockBinding{
		id:             id,
		secret:         secret,
		postBindFunc:   postBindFunc,
		postUnbindFunc: postUnbindFunc,
	}
}

func (m *mockBinding) ID() string {
	return m.id
}

func (m *mockBinding) Secret() string {
	return m.secret
}

func (m *mockBinding) GenerateKey(svc keys.StoredKeyService, kek []byte) error {
	key, err := crypto.NewKey()
	if err != nil {
		return err
	}

	pk, err := crypto.NewPublicKey(key)
	if err != nil {
		return err
	}

	skey := &keys.StoredKey{
		ID: m.id,
	}

	if err = skey.Encrypt(key, kek); err != nil {
		return err
	}

	if err = svc.Save(skey); err != nil {
		return err
	}

	m.publicKey = pk

	return nil
}

func (m *mockBinding) PublicKey() *jose.JsonWebKey {
	return m.publicKey
}

func (m *mockBinding) PrivateKey(svc keys.StoredKeyService, kek []byte) (*jose.JsonWebKey, error) {
	skey, err := svc.Get(m.id)
	if err != nil {
		return nil, err
	}

	return skey.Decrypt(kek)
}

func (m *mockBinding) Descriptor() document.ControllerDescriptor {
	return m.descriptor
}

func (m *mockBinding) SetDescriptor(desc document.ControllerDescriptor) error {
	m.descriptor = desc

	return nil
}

func (m *mockBinding) Bind(c *document.ControllerBinding) error {
	m.binding = c

	if m.postBindFunc != nil {
		m.postBindFunc(m)
	}

	return nil
}

func (m *mockBinding) Unbind() error {
	m.binding = nil

	if m.postUnbindFunc != nil {
		m.postUnbindFunc(m)
	}

	return nil
}

func (m *mockBinding) Certificate() string {
	if m.binding == nil {
		return ""
	}

	return m.binding.ControllerCertificate
}

func (m *mockBinding) Mandates() []string {
	if m.binding == nil {
		return nil
	}

	return m.binding.Mandates
}

func (m *mockBinding) AdminRoles() []string {
	if m.binding == nil {
		return []string{}
	}

	return m.binding.AdminRoles
}

func (m *mockBinding) Realm() *document.RealmDescriptor {
	if m.binding == nil {
		return nil
	}

	return m.binding.RealmDescriptor
}

func (m *mockBinding) ControllerBinding() *document.ControllerBinding {
	return m.binding
}

func (m *mockBinding) Status() string {
	return m.status
}

func (m *mockBinding) SetStatus(v string) error {
	m.status = v
	return nil
}

func (m *mockBinding) BindEndpoint() string {
	return m.bindEndpoint
}

func (m *mockBinding) SetBindEndpoint(v string) error {
	m.bindEndpoint = v
	return nil
}

type mockBindingService struct {
	bindings       map[string]Binding
	postBindFunc   func(Binding)
	postUnbindFunc func(Binding)
}

// NewMockBindingService returns a new mock implementation of the BindingService
func NewMockBindingService() BindingService {
	return &mockBindingService{
		bindings: make(map[string]Binding),
	}
}

func (s *mockBindingService) New(id string) (Binding, error) {
	b, ok := s.bindings[id]
	if ok {
		return b, errors.New("Binding already exists")
	}

	s.bindings[id] = newMockBinding(id, s.postBindFunc, s.postUnbindFunc)

	return s.bindings[id], nil
}

func (s *mockBindingService) Get(id string) (Binding, error) {
	b, ok := s.bindings[id]
	if !ok {
		return nil, errors.New("Binding not found")
	}

	return b, nil
}

func (s *mockBindingService) Delete(id string) error {
	_, ok := s.bindings[id]
	if !ok {
		return errors.New("Binding not found")
	}
	delete(s.bindings, id)
	return nil
}

func (s *mockBindingService) SetPostBind(f func(Binding)) {
	s.postBindFunc = f
}

func (s *mockBindingService) SetPostUnbind(f func(Binding)) {
	s.postUnbindFunc = f
}
