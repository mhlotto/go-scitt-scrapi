package scrapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/veraison/go-cose"
)

// NewEd25519Signer creates a COSE signer and returns signer, public key, and key identifier bytes.
func NewEd25519Signer(keyID string) (cose.Signer, ed25519.PublicKey, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("generate ed25519: %w", err)
	}
	signer, _, kid, err := NewEd25519SignerFromPrivate(priv, keyID)
	if err != nil {
		return nil, nil, nil, err
	}
	return signer, pub, kid, nil
}

// NewEd25519SignerFromPrivate creates a signer from an existing ed25519 private key.
func NewEd25519SignerFromPrivate(priv ed25519.PrivateKey, keyID string) (cose.Signer, ed25519.PublicKey, []byte, error) {
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("create signer: %w", err)
	}
	return signer, priv.Public().(ed25519.PublicKey), []byte(keyID), nil
}

// WrapPayloadAsCOSE produces a SignedStatement by signing the given payload with the provided signer and key ID.
func WrapPayloadAsCOSE(payload []byte, signer cose.Signer, keyID []byte) (SignedStatement, error) {
	msg := cose.NewSign1Message()
	msg.Payload = payload
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if len(keyID) > 0 {
		msg.Headers.Protected[cose.HeaderLabelKeyID] = keyID
	}
	// Optional type to aid downstream processing.
	_, _ = msg.Headers.Protected.SetContentType("application/cbor")
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return SignedStatement{}, fmt.Errorf("sign payload: %w", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return SignedStatement{}, fmt.Errorf("marshal sign1: %w", err)
	}
	return SignedStatement{Raw: raw, Msg: msg}, nil
}

// BuildSCITTStatement constructs a canonical SCITT envelope and signs it.
func BuildSCITTStatement(env StatementEnvelope, signer cose.Signer, kid []byte) (SignedStatement, error) {
	encoded, err := EncodeEnvelopeCanonical(env)
	if err != nil {
		return SignedStatement{}, err
	}
	msg := cose.NewSign1Message()
	msg.Payload = encoded
	msg.Headers.Protected.SetAlgorithm(signer.Algorithm())
	if len(kid) > 0 {
		msg.Headers.Protected[cose.HeaderLabelKeyID] = kid
	}
	// Mark the payload content type as SCITT envelope CBOR.
	_, _ = msg.Headers.Protected.SetContentType("application/scitt-statement+cbor")
	if err := msg.Sign(rand.Reader, nil, signer); err != nil {
		return SignedStatement{}, fmt.Errorf("sign statement: %w", err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		return SignedStatement{}, fmt.Errorf("marshal sign1: %w", err)
	}
	return SignedStatement{Raw: raw, Msg: msg}, nil
}

// NowUnix returns a UTC unix timestamp; separated for tests.
var NowUnix = func() int64 { return time.Now().UTC().Unix() }
