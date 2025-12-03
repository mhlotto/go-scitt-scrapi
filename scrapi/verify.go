package scrapi

import (
	"crypto"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

// VerificationInputs captures trusted keys for issuer and TS.
type VerificationInputs struct {
	IssuerKey crypto.PublicKey
	TSKey     crypto.PublicKey
}

// VerifyStatementAndReceipt validates issuer signature, TS receipt signature, statement hash binding,
// and Merkle inclusion proof against the tree head.
func VerifyStatementAndReceipt(statementRaw, receiptRaw []byte, trust VerificationInputs) error {
	if trust.IssuerKey == nil {
		return errors.New("issuer key is required")
	}
	if trust.TSKey == nil {
		return errors.New("transparency service key is required")
	}

	// Parse statement
	var stmt cose.Sign1Message
	if err := cbor.Unmarshal(statementRaw, &stmt); err != nil {
		return fmt.Errorf("parse statement COSE: %w", err)
	}
	issuerVerifier, err := cose.NewVerifier(stmt.Headers.AlgorithmMust(), trust.IssuerKey)
	if err != nil {
		return fmt.Errorf("issuer verifier: %w", err)
	}
	if err := stmt.Verify(nil, issuerVerifier); err != nil {
		return fmt.Errorf("verify statement signature: %w", err)
	}

	// Parse receipt
	var receiptMsg cose.Sign1Message
	if err := cbor.Unmarshal(receiptRaw, &receiptMsg); err != nil {
		return fmt.Errorf("parse receipt COSE: %w", err)
	}
	tsVerifier, err := cose.NewVerifier(receiptMsg.Headers.AlgorithmMust(), trust.TSKey)
	if err != nil {
		return fmt.Errorf("ts verifier: %w", err)
	}
	if err := receiptMsg.Verify(nil, tsVerifier); err != nil {
		return fmt.Errorf("verify receipt signature: %w", err)
	}

	var payload ReceiptPayload
	if err := cbor.Unmarshal(receiptMsg.Payload, &payload); err != nil {
		return fmt.Errorf("decode receipt payload: %w", err)
	}

	// Validate statement hash binding.
	stmtHash := sha256.Sum256(statementRaw)
	if !equalBytes(payload.StatementHash, stmtHash[:]) {
		return fmt.Errorf("statement hash mismatch")
	}

	if payload.TreeHead.TreeSize == 0 {
		return fmt.Errorf("invalid tree size in receipt")
	}
	if payload.LeafIndex >= payload.TreeHead.TreeSize {
		return fmt.Errorf("leaf index out of range")
	}

	leaf := merkleLeafHash(statementRaw)
	root := computeRootFromProof(leaf, payload.InclusionProof, payload.LeafIndex, payload.TreeHead.TreeSize)
	if !equalBytes(root, payload.TreeHead.RootHash) {
		return fmt.Errorf("inclusion proof mismatch with tree head")
	}

	return nil
}

func computeRootFromProof(leaf []byte, proof [][]byte, leafIndex, treeSize uint64) []byte {
	hash := leaf
	index := leafIndex
	last := treeSize - 1

	for _, sibling := range proof {
		if index%2 == 0 && index != last {
			hash = merkleNodeHash(hash, sibling)
		} else {
			hash = merkleNodeHash(sibling, hash)
		}
		index /= 2
		last /= 2
	}
	return hash
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
