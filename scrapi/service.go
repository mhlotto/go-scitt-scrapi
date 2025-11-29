package scrapi

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	tree       *MerkleTree
	signer     cose.Signer
	pubKey     ed25519.PublicKey
	keyID      []byte
	logID      string
	async      bool
	asyncDelay time.Duration
}

// NewInMemoryTransparencyService constructs an empty in-memory service.
func NewInMemoryTransparencyService() *InMemoryTransparencyService {
	return newInMemoryTransparencyService(false, 0)
}

// NewInMemoryTransparencyServiceAsync constructs an in-memory service that simulates async inclusion.
func NewInMemoryTransparencyServiceAsync(delay time.Duration) *InMemoryTransparencyService {
	return newInMemoryTransparencyService(true, delay)
}

func newInMemoryTransparencyService(async bool, delay time.Duration) *InMemoryTransparencyService {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(fmt.Errorf("generate ed25519 key: %w", err))
	}
	signer, err := cose.NewSigner(cose.AlgorithmEdDSA, priv)
	if err != nil {
		panic(fmt.Errorf("create signer: %w", err))
	}

	return &InMemoryTransparencyService{
		statements: make(map[string]SignedStatement),
		receipts:   make(map[string]*Receipt),
		statuses:   make(map[string]RegistrationStatus),
		tree:       &MerkleTree{},
		signer:     signer,
		pubKey:     pub,
		keyID:      []byte("demo-log-key"),
		logID:      "demo-log",
		audits:     make([]AuditRecord, 0, 32),
		async:      async,
		asyncDelay: delay,
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

	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotent: return existing receipt if the same statement digest was already registered.
	if existing, ok := s.receipts[id]; ok {
		s.audits = append(s.audits, AuditRecord{
			Time:    time.Now().UTC(),
			Event:   "register-duplicate",
			Locator: id,
			Status:  s.statuses[id],
			Detail:  fmt.Sprintf("bytes=%d", len(ss.Raw)),
		})
		return loc, existing, nil
	}

	s.statements[id] = ss

	if s.async {
		s.statuses[id] = StatusPending
		s.audits = append(s.audits, AuditRecord{
			Time:    time.Now().UTC(),
			Event:   "register-pending",
			Locator: id,
			Status:  StatusPending,
			Detail:  fmt.Sprintf("bytes=%d", len(ss.Raw)),
		})
		go s.completeAsync(id)
		return loc, nil, nil
	}

	leaf, root, path, size := s.tree.Append(ss.Raw)
	sizeUint, err := safeUint64(size)
	if err != nil {
		return Locator{}, nil, err
	}
	payload := ReceiptPayload{
		LogID:     s.logID,
		LeafHash:  leaf,
		RootHash:  root,
		TreeSize:  sizeUint,
		Path:      path,
		Timestamp: time.Now().UTC().Unix(),
	}
	payloadRaw, err := cbor.Marshal(payload)
	if err != nil {
		return loc, nil, fmt.Errorf("marshal receipt payload: %w", err)
	}

	receiptMsg := cose.NewSign1Message()
	receiptMsg.Payload = payloadRaw
	receiptMsg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	receiptMsg.Headers.Unprotected[cose.HeaderLabelKeyID] = s.keyID
	if err := receiptMsg.Sign(rand.Reader, nil, s.signer); err != nil {
		return loc, nil, fmt.Errorf("sign receipt: %w", err)
	}
	receiptRaw, err := receiptMsg.MarshalCBOR()
	if err != nil {
		return loc, nil, fmt.Errorf("marshal receipt: %w", err)
	}
	receipt := &Receipt{
		Raw: receiptRaw,
		Msg: receiptMsg,
	}

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

func (s *InMemoryTransparencyService) completeAsync(id string) {
	time.Sleep(s.asyncDelay)

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.statuses[id] != StatusPending {
		return
	}
	ss, ok := s.statements[id]
	if !ok {
		return
	}

	leaf, root, path, size := s.tree.Append(ss.Raw)
	sizeUint, err := safeUint64(size)
	if err != nil {
		return
	}
	payload := ReceiptPayload{
		LogID:     s.logID,
		LeafHash:  leaf,
		RootHash:  root,
		TreeSize:  sizeUint,
		Path:      path,
		Timestamp: time.Now().UTC().Unix(),
	}
	payloadRaw, err := cbor.Marshal(payload)
	if err != nil {
		return
	}

	receiptMsg := cose.NewSign1Message()
	receiptMsg.Payload = payloadRaw
	receiptMsg.Headers.Protected.SetAlgorithm(cose.AlgorithmEdDSA)
	receiptMsg.Headers.Unprotected[cose.HeaderLabelKeyID] = s.keyID
	if err := receiptMsg.Sign(rand.Reader, nil, s.signer); err != nil {
		return
	}
	receiptRaw, err := receiptMsg.MarshalCBOR()
	if err != nil {
		return
	}
	receipt := &Receipt{
		Raw: receiptRaw,
		Msg: receiptMsg,
	}

	s.receipts[id] = receipt
	s.statuses[id] = StatusSuccess
	s.audits = append(s.audits, AuditRecord{
		Time:    time.Now().UTC(),
		Event:   "register-complete",
		Locator: id,
		Status:  StatusSuccess,
		Detail:  fmt.Sprintf("bytes=%d", len(ss.Raw)),
	})
}

func safeUint64(v int) (uint64, error) {
	if v < 0 {
		return 0, fmt.Errorf("negative size: %d", v)
	}
	// int cannot exceed math.MaxUint64 on this platform; still add a #nosec guard for gosec.
	// #nosec G115
	return uint64(v), nil
}

// AuditTrail returns a copy of the collected audit records.
func (s *InMemoryTransparencyService) AuditTrail() []AuditRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]AuditRecord, len(s.audits))
	copy(out, s.audits)
	return out
}

// LogPublicKey returns the Ed25519 public key used to sign receipts.
func (s *InMemoryTransparencyService) LogPublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey{}, s.pubKey...)
}

// LogKeyID returns the COSE key identifier used in receipts.
func (s *InMemoryTransparencyService) LogKeyID() []byte {
	return append([]byte{}, s.keyID...)
}

// LogID returns the logical log identifier for receipts.
func (s *InMemoryTransparencyService) LogID() string {
	return s.logID
}
