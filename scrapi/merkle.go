package scrapi

import (
	"crypto/sha256"
)

// merkleLeaf and merkleNode hashes use simple domain separation to avoid collisions.
func merkleLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func merkleNode(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ProofNode describes a single step in a Merkle inclusion path.
type ProofNode struct {
	Position string `cbor:"pos"` // "left" or "right"
	Hash     []byte `cbor:"hash"`
}

// MerkleTree is a simple append-only Merkle tree used for demo receipts.
type MerkleTree struct {
	leaves [][]byte
}

// Append adds a new leaf, returning the leaf hash, root, proof path, and new size.
func (t *MerkleTree) Append(data []byte) (leaf []byte, root []byte, proof []ProofNode, size int) {
	leaf = merkleLeaf(data)
	t.leaves = append(t.leaves, leaf)
	proof = t.buildProof(len(t.leaves) - 1)
	root = t.currentRoot()
	return leaf, root, proof, len(t.leaves)
}

func (t *MerkleTree) currentRoot() []byte {
	if len(t.leaves) == 0 {
		zero := sha256.Sum256(nil)
		return zero[:]
	}
	level := make([][]byte, len(t.leaves))
	copy(level, t.leaves)

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			parent := merkleNode(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}

func (t *MerkleTree) buildProof(idx int) []ProofNode {
	if idx < 0 || idx >= len(t.leaves) {
		return nil
	}
	var proof []ProofNode

	level := make([][]byte, len(t.leaves))
	copy(level, t.leaves)
	pos := idx

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			parent := merkleNode(left, right)
			next = append(next, parent)

			if i == pos || i+1 == pos {
				if i+1 < len(level) {
					if i == pos {
						proof = append(proof, ProofNode{Position: "right", Hash: right})
					} else {
						proof = append(proof, ProofNode{Position: "left", Hash: left})
					}
				} else {
					// odd node duplicated; still note the sibling (same hash)
					proof = append(proof, ProofNode{Position: "right", Hash: right})
				}
				pos = len(next) - 1
			}
		}
		level = next
	}

	return proof
}
