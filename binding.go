package controller

import (
	"github.com/Brickchain/go-document.v2"
	keys "gitlab.brickchain.com/libs/go-keys.v1"
	jose "gopkg.in/square/go-jose.v1"
)

// Binding describes the methods for managing a specific binding with it's related configuration.
type Binding interface {

	// ID returns the ID of the binding.
	ID() string

	// Secret for the binding.
	Secret() string

	// GenerateKey will generate a new keypair for this binding.
	GenerateKey(keys.StoredKeyService, []byte) error

	// PublicKey of the binding.
	PublicKey() *jose.JsonWebKey

	// PrivateKey of the binding. Requires a StoredKeyService and a Key Encryption Key (KEK).
	PrivateKey(keys.StoredKeyService, []byte) (*jose.JsonWebKey, error)

	// Descriptor returns the ControllerDescriptor for this binding
	Descriptor() document.ControllerDescriptor

	// SetDescriptor sets the ControllerDescriptor for this binding
	SetDescriptor(document.ControllerDescriptor) error

	// Bind is used when the realm binds to this binding.
	Bind(*document.ControllerBinding) error

	// Unbind removes the realm binding
	Unbind() error

	// Certificate of the binding.
	Certificate() string

	// Mandates returns the mandates we got from the realm.
	Mandates() []string

	// AdminRoles returns the list of roles that can administer this binding.
	AdminRoles() []string

	// Realm returns the realm-descriptor that was used for this binding.
	Realm() *document.RealmDescriptor

	// ControllerBinding returns the controller-binding document.
	ControllerBinding() *document.ControllerBinding

	// Status is used to tell the realm if this binding requires some extra setup steps.
	Status() string

	// SetStatus updates the Status value.
	SetStatus(string) error

	// BindEndpoint returns the endpoint where the realm should post the controller-binding.
	BindEndpoint() string

	// SetBindEndpoint updates the BindEndpoint value.
	SetBindEndpoint(string) error
}
