package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/pkg/errors"

	"github.com/Brickchain/go-crypto.v2"
	"github.com/Brickchain/go-document.v2"
	httphandler "github.com/Brickchain/go-httphandler.v2"
	jose "gopkg.in/square/go-jose.v1"
)

// ControllerDescriptorHandler is a helper for publishing the controller-descriptor on an endpoint
func ControllerDescriptorHandler(req httphandler.RequestWithBinding) httphandler.Response {
	if req.URL().Query().Get("secret") != req.Binding().Secret() {
		return httphandler.NewErrorResponse(http.StatusForbidden, errors.New("Wrong secret"))
	}

	descriptor := req.Binding().Descriptor()

	descriptor.Key = req.Binding().PublicKey()
	descriptor.Status = req.Binding().Status()

	if !strings.Contains(descriptor.AdminUI, "binding=") {
		separator := "?"
		if strings.Contains(descriptor.AdminUI, "?") {
			separator = "&"
		}
		descriptor.AdminUI = fmt.Sprintf("%s%sbinding=%s", descriptor.AdminUI, separator, req.Binding().ID())
	}

	return httphandler.NewJsonResponse(http.StatusOK, descriptor)
}

// BindingCallback handles the controller-binding response
func BindingCallback(req httphandler.RequestWithBinding) httphandler.Response {

	if req.URL().Query().Get("secret") != req.Binding().Secret() {
		return httphandler.NewErrorResponse(http.StatusForbidden, errors.New("Wrong secret"))
	}

	body, err := req.Body()
	if err != nil {
		return httphandler.NewErrorResponse(http.StatusInternalServerError, errors.Wrap(err, "failed to read body"))
	}

	var signer *jose.JsonWebKey
	if strings.Contains(string(body), "\"payload\"") {
		jws, err := crypto.UnmarshalSignature(body)
		if err != nil {
			return httphandler.NewErrorResponse(http.StatusInternalServerError, errors.Wrap(err, "failed to unmarshal JWS"))
		}

		if len(jws.Signatures) < 1 {
			return httphandler.NewErrorResponse(http.StatusBadRequest, errors.New("No signature on JWS"))
		}

		signer = jws.Signatures[0].Header.JsonWebKey
		body, err = jws.Verify(signer)
		if err != nil {
			return httphandler.NewErrorResponse(http.StatusBadRequest, errors.Wrap(err, "failed to verify signature"))
		}
	}

	var payload *document.ControllerBinding
	err = json.Unmarshal(body, &payload)
	if err != nil {
		return httphandler.NewErrorResponse(http.StatusInternalServerError, errors.Wrap(err, "failed to unmarshal payload"))
	}

	if signer != nil {
		if crypto.Thumbprint(signer) != crypto.Thumbprint(payload.RealmDescriptor.PublicKey) {
			return httphandler.NewErrorResponse(http.StatusBadRequest, errors.New("Payload not signed by realm"))
		}
	}

	if err = req.Binding().Bind(payload); err != nil {
		return httphandler.NewErrorResponse(http.StatusInternalServerError, errors.Wrap(err, "failed to bind"))
	}

	return httphandler.NewEmptyResponse(http.StatusCreated)
}
