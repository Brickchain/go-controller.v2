package controller

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/Brickchain/go-crypto.v2"
	"github.com/Brickchain/go-document.v2"
	jose "gopkg.in/square/go-jose.v1"
)

// VerifyMandateToken is used to verify that a mandate-token is correctly signed
func VerifyMandateToken(token string, mandateSigner *jose.JsonWebKey, keyLevel int) ([]*document.Mandate, *jose.JsonWebKey, error) {
	tokenJWS, err := crypto.UnmarshalSignature([]byte(token))
	if err != nil {
		return nil, nil, err
	}

	if len(tokenJWS.Signatures) < 1 {
		return nil, nil, fmt.Errorf("No signers of token")
	}

	clientKey := tokenJWS.Signatures[0].Header.JsonWebKey

	tokenPayload, err := tokenJWS.Verify(clientKey)
	if err != nil {
		return nil, nil, err
	}

	var mandateToken *document.MandateToken
	err = json.Unmarshal(tokenPayload, &mandateToken)
	if err != nil {
		return nil, nil, err
	}

	if mandateToken.Timestamp.Add(time.Second * time.Duration(mandateToken.TTL)).Before(time.Now().UTC()) {
		return nil, nil, fmt.Errorf("Token has expired")
	}

	if mandateToken.Certificate != "" {
		certChain, err := crypto.VerifyCertificate(mandateToken.Certificate, keyLevel)
		if err != nil {
			return nil, nil, err
		}

		clientKey = certChain.Issuer
	}

	mandates := make([]*document.Mandate, 0)
	for _, mandateString := range mandateToken.Mandates {
		mandateJWS, err := crypto.UnmarshalSignature([]byte(mandateString))
		if err != nil {
			return mandates, nil, err
		}

		if len(mandateJWS.Signatures) < 1 {
			return mandates, nil, fmt.Errorf("No signers of mandate")
		}

		if crypto.Thumbprint(mandateJWS.Signatures[0].Header.JsonWebKey) != crypto.Thumbprint(mandateSigner) {
			return mandates, nil, fmt.Errorf("Mandate not signed by correct key")
		}

		mandatePayload, err := mandateJWS.Verify(mandateSigner)
		if err != nil {
			return mandates, nil, err
		}

		var mandate *document.Mandate
		if err := json.Unmarshal(mandatePayload, &mandate); err != nil {
			return mandates, nil, err
		}

		if mandate.ValidFrom.Before(time.Now().UTC()) {
			return mandates, nil, fmt.Errorf("Mandate not yet valid")
		}

		if mandate.ValidUntil.After(time.Now().UTC()) {
			return mandates, nil, fmt.Errorf("Mandate has expired")
		}

		mandates = append(mandates, mandate)
	}

	return mandates, clientKey, err
}
