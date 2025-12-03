package scrapi

import "github.com/veraison/go-cose"

// SignedStatement holds the original COSE_Sign1 payload and a parsed form.
type SignedStatement struct {
	Raw []byte
	Msg *cose.Sign1Message
}

// Receipt represents a COSE_Sign1 receipt returned by a transparency service.
type Receipt struct {
	Raw []byte
	Msg *cose.Sign1Message
}

// ReceiptPayload describes the signed content inside a receipt.
type ReceiptPayload struct {
	LogID     string      `cbor:"log_id,omitempty"`
	LeafHash  []byte      `cbor:"leaf"`
	RootHash  []byte      `cbor:"root"`
	TreeSize  uint64      `cbor:"size"`
	Path      []ProofNode `cbor:"path"`
	Timestamp int64       `cbor:"ts"`
}

// STHPayload describes the signed content of a Signed Tree Head.
type STHPayload struct {
	LogID     string `cbor:"log_id,omitempty"`
	RootHash  []byte `cbor:"root"`
	TreeSize  uint64 `cbor:"size"`
	HashAlg   string `cbor:"hash_alg,omitempty"`
	Timestamp int64  `cbor:"ts"`
}

// RegistrationStatus tracks the state of a registration.
type RegistrationStatus string

const (
	StatusPending RegistrationStatus = "pending"
	StatusSuccess RegistrationStatus = "success"
	StatusFailed  RegistrationStatus = "failed"
)

// Locator identifies a registered statement.
type Locator struct {
	ID  string
	URL string
}

// ProblemDetails mirrors Concise Problem Details fields used on the wire.
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Status   int    `json:"status,omitempty"`
	Instance string `json:"instance,omitempty"`
}
