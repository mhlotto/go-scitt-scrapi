package scrapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"github.com/veraison/go-cose"
)

// NewEd25519Signer creates a COSE signer and returns signer, public key, and key identifier bytes.
func NewEd25519Signer(keyID string) (cose.Signer, ed25519.PublicKey, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate ed25519: %w", err)
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, pub, []byte(keyID), nil
}

// WrapPayloadAsCOSE produces a SignedStatement by signing the given payload with the provided signer and key ID.
func WrapPayloadAsCOSE(payload []byte, signer cose.Signer, keyID []byte) (SignedStatement, error) {
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if len(keyID) > 0 {
		msg.Headers.Unprotected[cose.HeaderLabelKeyID] = keyID
	}
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return SignedStatement{}, fmt.Errorf("sign payload: %w", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return SignedStatement{}, fmt.Errorf("marshal sign1: %w", err)
	}
	return SignedStatement{Raw: raw, Msg: msg}, nil
}
