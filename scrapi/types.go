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

// ReceiptPayload describes the signed content inside a receipt, following SCITT receipt structure.
type ReceiptPayload struct {
	StatementHash  []byte         `cbor:"statement_hash"`
	TreeHead       TreeHead       `cbor:"tree_head"`
	InclusionProof [][]byte       `cbor:"inclusion_proof"`
	LeafIndex      uint64         `cbor:"leaf_index"`
	Extensions     map[string]any `cbor:"extensions,omitempty"`
}

// TreeHead captures the tree head embedded in receipts and STHs.
type TreeHead struct {
	LogID         string `cbor:"log_id,omitempty"`
	RootHash      []byte `cbor:"root_hash"`
	TreeSize      uint64 `cbor:"tree_size"`
	HashAlg       string `cbor:"hash_alg,omitempty"`
	TreeType      string `cbor:"tree_type,omitempty"`
	ScrapiVersion string `cbor:"scrapi_version,omitempty"`
	Timestamp     int64  `cbor:"timestamp"`
}

// STHPayload describes the signed content of a Signed Tree Head.
type STHPayload struct {
	TreeHead TreeHead `cbor:"tree_head"`
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
