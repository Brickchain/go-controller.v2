package gorm

import (
	"encoding/json"
	"strings"

	controller "github.com/Brickchain/go-controller.v2"
	"github.com/Brickchain/go-crypto.v2"
	"github.com/Brickchain/go-document.v2"
	"github.com/jinzhu/gorm"
	keys "gitlab.brickchain.com/libs/go-keys.v1"
	jose "gopkg.in/square/go-jose.v1"
)

type gormBinding struct {
	db             *gorm.DB
	DBid           string `gorm:"column:id;primary_key"`
	DBsecret       string `gorm:"column:secret"`
	DBpublicKey    string `gorm:"column:public_key"`
	DBdescriptor   string `gorm:"column:descriptor"`
	DBbinding      string `gorm:"column:binding"`
	DBcertificate  string `gorm:"column:certificate"`
	DBmandates     string `gorm:"column:mandates"`
	DBadminRoles   string `gorm:"column:admin_roles"`
	DBrealm        string `gorm:"column:realm"`
	DBstatus       string `gorm:"column:status"`
	DBbindEndpoint string `gorm:"column:bind_endpoint"`
	postBindFunc   func(controller.Binding)
	postUnbindFunc func(controller.Binding)
}

func newGormBinding(db *gorm.DB, id string, postBindFunc, postUnbindFunc func(controller.Binding)) *gormBinding {
	secret, _ := crypto.GenerateRandomString(42)
	return &gormBinding{
		db:             db,
		DBid:           id,
		DBsecret:       secret,
		postBindFunc:   postBindFunc,
		postUnbindFunc: postUnbindFunc,
	}
}

func (g *gormBinding) save() error {
	return g.db.Save(g).Error
}

// ID returns the ID of the binding.
func (g *gormBinding) ID() string {
	return g.DBid
}

// Secret for the binding.
func (g *gormBinding) Secret() string {
	return g.DBsecret
}

// GenerateKey will generate a new keypair for this binding.
func (g *gormBinding) GenerateKey(svc keys.StoredKeyService, kek []byte) error {
	key, err := crypto.NewKey()
	if err != nil {
		return err
	}

	pk, err := crypto.NewPublicKey(key)
	if err != nil {
		return err
	}

	skey := &keys.StoredKey{
		ID: g.DBid,
	}

	if err = skey.Encrypt(key, kek); err != nil {
		return err
	}

	if err = svc.Save(skey); err != nil {
		return err
	}

	if err = g.setPublicKey(pk); err != nil {
		return err
	}

	return svc.Save(skey)
}

// PublicKey of the binding.
func (g *gormBinding) PublicKey() *jose.JsonWebKey {
	key, _ := crypto.UnmarshalKey([]byte(g.DBpublicKey))
	return key
}

func (g *gormBinding) setPublicKey(key *jose.JsonWebKey) error {
	bytes, err := json.Marshal(key)
	if err != nil {
		return err
	}

	g.DBpublicKey = string(bytes)

	return g.save()
}

// PrivateKey of the binding. Requires a StoredKeyService and a Key Encryption Key (KEK).
func (g *gormBinding) PrivateKey(svc keys.StoredKeyService, kek []byte) (*jose.JsonWebKey, error) {
	skey, err := svc.Get(g.DBid)
	if err != nil {
		return nil, err
	}

	return skey.Decrypt(kek)
}

func (g *gormBinding) Descriptor() document.ControllerDescriptor {
	desc := document.ControllerDescriptor{}
	json.Unmarshal([]byte(g.DBdescriptor), &desc)

	return desc
}

func (g *gormBinding) SetDescriptor(desc document.ControllerDescriptor) error {
	bytes, err := json.Marshal(desc)
	if err != nil {
		return err
	}

	g.DBdescriptor = string(bytes)
	return g.save()
}

// Bind is used when the realm binds to this binding.
func (g *gormBinding) Bind(c *document.ControllerBinding) error {
	g.DBcertificate = c.ControllerCertificate
	g.DBmandates = strings.Join(c.Mandates, ",")
	g.setAdminRoles(c.AdminRoles)

	if err := g.setRealm(c.RealmDescriptor); err != nil {
		return err
	}

	if err := g.setControllerBinding(c); err != nil {
		return err
	}

	if err := g.save(); err != nil {
		return err
	}

	if g.postBindFunc != nil {
		g.postBindFunc(g)
	}

	return nil
}

// Unbind removes the realm binding
func (g *gormBinding) Unbind() error {
	g.DBcertificate = ""
	g.DBmandates = ""
	g.DBadminRoles = ""
	g.DBrealm = ""
	g.DBbinding = ""

	if g.postUnbindFunc != nil {
		g.postUnbindFunc(g)
	}

	return g.save()
}

// CertificateChain of the binding.
func (g *gormBinding) Certificate() string {
	return g.DBcertificate
}

// Mandate returns the mandate we got from the realm.
func (g *gormBinding) Mandates() []string {
	if g.DBmandates == "" {
		return []string{}
	}
	return strings.Split(g.DBmandates, ",")
}

// AdminRoles returns the list of roles that can administer this binding.
func (g *gormBinding) AdminRoles() []string {
	if g.DBadminRoles == "" {
		return []string{}
	}
	return strings.Split(g.DBadminRoles, ",")
}

func (g *gormBinding) setAdminRoles(roles []string) {
	g.DBadminRoles = strings.Join(roles, ",")
}

// Realm returns the realm-descriptor that was used for this binding.
func (g *gormBinding) Realm() *document.RealmDescriptor {
	realm := &document.RealmDescriptor{}
	if err := json.Unmarshal([]byte(g.DBrealm), &realm); err != nil {
		return nil
	}

	return realm
}

func (g *gormBinding) setRealm(realm *document.RealmDescriptor) error {
	bytes, err := json.Marshal(realm)
	if err != nil {
		return err
	}

	g.DBrealm = string(bytes)

	return nil
}

// ControllerBinding returns the controller-binding document.
func (g *gormBinding) ControllerBinding() *document.ControllerBinding {
	c := &document.ControllerBinding{}
	if err := json.Unmarshal([]byte(g.DBbinding), &c); err != nil {
		return nil
	}

	return c
}

func (g *gormBinding) setControllerBinding(c *document.ControllerBinding) error {
	bytes, err := json.Marshal(c)
	if err != nil {
		return err
	}

	g.DBbinding = string(bytes)

	return nil
}

// Status is used to tell the realm if this binding requires some extra setup steps.
func (g *gormBinding) Status() string {
	return g.DBstatus
}

// SetStatus updates the Status value.
func (g *gormBinding) SetStatus(v string) error {
	g.DBstatus = v

	return g.save()
}

// BindEndpoint returns the endpoint where the realm should post the controller-binding.
func (g *gormBinding) BindEndpoint() string {
	return g.DBbindEndpoint
}

// SetBindEndpoint updates the BindEndpoint value.
func (g *gormBinding) SetBindEndpoint(v string) error {
	g.DBbindEndpoint = v

	return g.save()
}
