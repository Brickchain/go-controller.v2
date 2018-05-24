package controller

// BindingService describes the methods needed to manage bindings
type BindingService interface {
	// New creates a new Binding with an ID.
	// Trying to create a binding with an already existing ID should return an error.
	New(id string) (Binding, error)

	// Get a Binding by ID
	Get(id string) (Binding, error)

	// Delete a Binding by ID
	Delete(id string) error

	// SetPostBind is run after a Binding has been bound by a Realm
	SetPostBind(func(Binding))

	// SetPostUnbind is run after a Binding has been unbound by a Realm
	SetPostUnbind(func(Binding))
}
