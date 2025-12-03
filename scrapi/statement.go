package scrapi

import (
	"errors"

	"github.com/fxamacker/cbor/v2"
)

var canonicalEncMode = func() cbor.EncMode {
	opts := cbor.EncOptions{
		Sort:          cbor.SortCoreDeterministic,
		TimeTag:       cbor.EncTagNone,
		ShortestFloat: cbor.ShortestFloat16,
	}
	mode, err := opts.EncMode()
	if err != nil {
		panic(err)
	}
	return mode
}()

// StatementEnvelope is a SCITT-style envelope that binds an artifact subject to payload bytes.
type StatementEnvelope struct {
	Type        string             `cbor:"type"`
	Subject     []StatementSubject `cbor:"subject"`
	ContentType string             `cbor:"contentType"`
	Payload     []byte             `cbor:"payload"`
}

// StatementSubject captures artifact identity for the statement.
type StatementSubject struct {
	URI    string            `cbor:"uri,omitempty"`
	Digest map[string]string `cbor:"digest,omitempty"`
}

// EncodeEnvelopeCanonical encodes the envelope using deterministic CBOR for signing.
func EncodeEnvelopeCanonical(env StatementEnvelope) ([]byte, error) {
	if err := validateEnvelope(env); err != nil {
		return nil, err
	}
	return canonicalEncMode.Marshal(env)
}

// DecodeEnvelope parses an envelope and enforces required fields.
func DecodeEnvelope(data []byte) (StatementEnvelope, error) {
	var env StatementEnvelope
	if err := cbor.Unmarshal(data, &env); err != nil {
		return StatementEnvelope{}, err
	}
	if err := validateEnvelope(env); err != nil {
		return StatementEnvelope{}, err
	}
	return env, nil
}

func validateEnvelope(env StatementEnvelope) error {
	if env.Type == "" {
		return errors.New("envelope type required")
	}
	if env.ContentType == "" {
		return errors.New("envelope contentType required")
	}
	if len(env.Subject) == 0 {
		return errors.New("envelope subject required")
	}
	for i, subj := range env.Subject {
		if subj.URI == "" {
			return errors.New("subject uri required")
		}
		if len(subj.Digest) == 0 {
			return errors.New("subject digest required")
		}
		for alg, val := range subj.Digest {
			if alg == "" || val == "" {
				return errors.New("subject digest entries must be non-empty")
			}
		}
		// Basic guard against empty slice entries.
		if i < 0 {
			return errors.New("invalid subject index")
		}
	}
	if len(env.Payload) == 0 {
		return errors.New("envelope payload required")
	}
	return nil
}
