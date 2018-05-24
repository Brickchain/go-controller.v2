package handlers

import (
	controller "github.com/Brickchain/go-controller.v2"
	httphandler "github.com/Brickchain/go-httphandler.v2"
	"github.com/julienschmidt/httprouter"
)

// ControllerWrapper is a wrapper that adds some WithBinding request types
type ControllerWrapper struct {
	w    *httphandler.Wrapper
	bsvc controller.BindingService
}

// NewControllerWrapper returns a new ControllerWrapper instance
func NewControllerWrapper(w *httphandler.Wrapper, bsvc controller.BindingService) *ControllerWrapper {
	return &ControllerWrapper{
		w:    w,
		bsvc: bsvc,
	}
}

// Wrap is the main wrapper for making the regular httprouter.Handle type in to our Request/Response types
func (wrapper *ControllerWrapper) Wrap(h interface{}) httprouter.Handle {
	switch x := h.(type) {
	case func(RequestWithBinding) httphandler.Response:
		return wrapper.w.Wrap(addBinding(wrapper.bsvc, x))
	case func(AuthenticatedRequestWithBinding) httphandler.Response:

		return wrapper.w.Wrap(addAuthenticatedBinding(wrapper.bsvc, x))
	case func(ActionRequestWithBinding) httphandler.Response:
		return wrapper.w.Wrap(addActionBinding(wrapper.bsvc, x))
	}

	return wrapper.w.Wrap(h)
}
