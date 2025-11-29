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
	Type   string `json:"type,omitempty"`
	Title  string `json:"title,omitempty"`
	Detail string `json:"detail,omitempty"`
}
