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

	// Enforce subject/digest binding for sha256 if present.
	env, err := DecodeEnvelope(stmt.Payload)
	if err != nil {
		return fmt.Errorf("decode envelope: %w", err)
	}
	if len(env.Subject) > 0 {
		sbomDigest := sha256.Sum256(env.Payload)
		for _, subj := range env.Subject {
			if val, ok := subj.Digest["sha256"]; ok {
				if val != fmt.Sprintf("%x", sbomDigest[:]) {
					return fmt.Errorf("subject digest mismatch for sha256")
				}
			}
		}
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

// VerifySTH validates a signed tree head using the TS key.
func VerifySTH(sthRaw []byte, tsKey crypto.PublicKey) (TreeHead, error) {
	var msg cose.Sign1Message
	if err := cbor.Unmarshal(sthRaw, &msg); err != nil {
		return TreeHead{}, fmt.Errorf("parse STH COSE: %w", err)
	}
	verifier, err := cose.NewVerifier(msg.Headers.AlgorithmMust(), tsKey)
	if err != nil {
		return TreeHead{}, fmt.Errorf("ts verifier: %w", err)
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return TreeHead{}, fmt.Errorf("verify STH signature: %w", err)
	}
	var payload STHPayload
	if err := cbor.Unmarshal(msg.Payload, &payload); err != nil {
		return TreeHead{}, fmt.Errorf("decode STH payload: %w", err)
	}
	if payload.TreeHead.TreeSize == 0 {
		return TreeHead{}, fmt.Errorf("invalid tree size in STH")
	}
	if payload.TreeHead.Timestamp == 0 {
		return TreeHead{}, fmt.Errorf("missing timestamp in STH")
	}
	return payload.TreeHead, nil
}

// VerifyConsistencyProof checks an RFC6962/9162 consistency proof between two tree heads.
func VerifyConsistencyProof(proof [][]byte, firstSize, secondSize uint64, firstRoot, secondRoot []byte) error {
	if firstSize == 0 || firstSize > secondSize {
		return fmt.Errorf("invalid sizes")
	}
	if firstSize == secondSize {
		if len(proof) != 0 {
			return fmt.Errorf("unexpected proof entries for equal sizes")
		}
		if !equalBytes(firstRoot, secondRoot) {
			return fmt.Errorf("root mismatch for equal sizes")
		}
		return nil
	}
	if len(proof) == 0 {
		return fmt.Errorf("empty proof")
	}

	fn := firstSize - 1
	sn := secondSize - 1

	var fr, sr []byte
	// Skip common right edges.
	for fn&1 == 0 {
		fn >>= 1
		sn >>= 1
	}
	fr = proof[0]
	sr = proof[0]
	idx := 1

	for fn != 0 {
		if idx >= len(proof) {
			return fmt.Errorf("proof too short")
		}
		switch {
		case sn&1 == 1:
			fr = merkleNodeHash(proof[idx], fr)
			sr = merkleNodeHash(proof[idx], sr)
			idx++
		default:
			sr = merkleNodeHash(sr, proof[idx])
			idx++
		}
		fn >>= 1
		sn >>= 1
		for fn&1 == 0 {
			fn >>= 1
			sn >>= 1
		}
	}
	for idx < len(proof) {
		sr = merkleNodeHash(sr, proof[idx])
		idx++
	}

	if !equalBytes(fr, firstRoot) {
		return fmt.Errorf("first root mismatch")
	}
	if !equalBytes(sr, secondRoot) {
		return fmt.Errorf("second root mismatch")
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
