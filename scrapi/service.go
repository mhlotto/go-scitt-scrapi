package scrapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// TransparencyService describes the minimal operations of a transparency log.
type TransparencyService interface {
	Register(ctx context.Context, ss SignedStatement) (Locator, *Receipt, error)
	QueryStatus(ctx context.Context, loc Locator) (RegistrationStatus, *Receipt, error)
	ResolveReceipt(ctx context.Context, id string) (*Receipt, error)
}

// AuditRecord tracks notable service events for operators.
type AuditRecord struct {
	Time    time.Time
	Event   string
	Locator string
	Status  RegistrationStatus
	Detail  string
}

// InMemoryTransparencyService is a toy implementation useful for demos and tests.
type InMemoryTransparencyService struct {
	mu         sync.RWMutex
	statements map[string]SignedStatement
	receipts   map[string]*Receipt
	statuses   map[string]RegistrationStatus
	audits     []AuditRecord
}

// NewInMemoryTransparencyService constructs an empty in-memory service.
func NewInMemoryTransparencyService() *InMemoryTransparencyService {
	return &InMemoryTransparencyService{
		statements: make(map[string]SignedStatement),
		receipts:   make(map[string]*Receipt),
		statuses:   make(map[string]RegistrationStatus),
		audits:     make([]AuditRecord, 0, 32),
	}
}

// Register stores the signed statement and immediately produces a dummy receipt.
func (s *InMemoryTransparencyService) Register(ctx context.Context, ss SignedStatement) (Locator, *Receipt, error) {
	_ = ctx

	if len(ss.Raw) == 0 {
		return Locator{}, nil, fmt.Errorf("signed statement is empty")
	}

	digest := sha256.Sum256(ss.Raw)
	id := hex.EncodeToString(digest[:])
	loc := Locator{ID: id}

	receiptMsg := cose.Sign1Message{
		Payload: digest[:],
	}
	receiptRaw, err := cbor.Marshal(receiptMsg)
	if err != nil {
		return loc, nil, fmt.Errorf("marshal receipt: %w", err)
	}
	receipt := &Receipt{
		Raw: receiptRaw,
		Msg: &receiptMsg,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.statements[id] = ss
	s.receipts[id] = receipt
	s.statuses[id] = StatusSuccess
	s.audits = append(s.audits, AuditRecord{
		Time:    time.Now().UTC(),
		Event:   "register",
		Locator: id,
		Status:  StatusSuccess,
		Detail:  fmt.Sprintf("bytes=%d", len(ss.Raw)),
	})

	return loc, receipt, nil
}

// QueryStatus returns the current registration status for a locator.
func (s *InMemoryTransparencyService) QueryStatus(ctx context.Context, loc Locator) (RegistrationStatus, *Receipt, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	status, ok := s.statuses[loc.ID]
	if !ok {
		return "", nil, fmt.Errorf("locator not found")
	}

	s.audits = append(s.audits, AuditRecord{
		Time:    time.Now().UTC(),
		Event:   "query-status",
		Locator: loc.ID,
		Status:  status,
	})

	return status, s.receipts[loc.ID], nil
}

// ResolveReceipt fetches a receipt by ID.
func (s *InMemoryTransparencyService) ResolveReceipt(ctx context.Context, id string) (*Receipt, error) {
	_ = ctx

	s.mu.Lock()
	defer s.mu.Unlock()

	receipt, ok := s.receipts[id]
	if !ok {
		return nil, errors.New("receipt not found")
	}

	s.audits = append(s.audits, AuditRecord{
		Time:    time.Now().UTC(),
		Event:   "resolve-receipt",
		Locator: id,
		Status:  s.statuses[id],
	})

	return receipt, nil
}

// AuditTrail returns a copy of the collected audit records.
func (s *InMemoryTransparencyService) AuditTrail() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]AuditRecord, len(s.audits))
	copy(out, s.audits)
	return out
}
