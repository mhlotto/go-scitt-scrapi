package scrapi

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
)

// MerkleLeafHash computes a leaf hash with domain separation.
func MerkleLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

// MerkleNodeHash computes a parent hash with domain separation.
func MerkleNodeHash(left, right []byte) []byte {
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
	leaf = MerkleLeafHash(data)
	t.leaves = append(t.leaves, leaf)
	proof = t.buildProof(len(t.leaves) - 1)
	root = t.currentRoot()
	return leaf, root, proof, len(t.leaves)
}

// Root returns the current tree root.
func (t *MerkleTree) Root() []byte {
	return t.currentRoot()
}

// Size returns the number of leaves in the tree.
func (t *MerkleTree) Size() int {
	return len(t.leaves)
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
			parent := MerkleNodeHash(left, right)
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
			parent := MerkleNodeHash(left, right)
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

// ConsistencyProof returns a CT-style consistency proof from firstSize to secondSize.
// firstSize must be > 0 and <= secondSize; secondSize must be <= current size.
func (t *MerkleTree) ConsistencyProof(firstSize, secondSize int) ([]ProofNode, error) {
	if firstSize <= 0 {
		return nil, fmt.Errorf("first size must be positive")
	}
	if firstSize > secondSize {
		return nil, fmt.Errorf("first size (%d) greater than second size (%d)", firstSize, secondSize)
	}
	if secondSize > len(t.leaves) {
		return nil, fmt.Errorf("second size (%d) exceeds tree size (%d)", secondSize, len(t.leaves))
	}
	if firstSize == secondSize {
		return nil, nil
	}

	var proof [][]byte
	buildConsistencyProof(t.leaves[:secondSize], firstSize, secondSize, &proof)

	out := make([]ProofNode, len(proof))
	for i, h := range proof {
		out[i] = ProofNode{Position: "consistency", Hash: h}
	}
	return out, nil
}

// buildConsistencyProof implements RFC6962 section 2.1.2 for a slice of leaf hashes.
func buildConsistencyProof(leaves [][]byte, firstSize, secondSize int, proof *[][]byte) {
	if firstSize == secondSize {
		return
	}

	k := largestPowerOfTwoLessThan(secondSize)

	switch {
	case firstSize <= k:
		// proof for (m, k) plus subtree hash for right sibling
		buildConsistencyProof(leaves[:k], firstSize, k, proof)
		*proof = append(*proof, merkleRoot(leaves[k:secondSize]))
	case firstSize > k:
		// proof for (m-k, n-k) plus subtree hash for left sibling
		buildConsistencyProof(leaves[k:secondSize], firstSize-k, secondSize-k, proof)
		*proof = append(*proof, merkleRoot(leaves[:k]))
	}
}

func largestPowerOfTwoLessThan(n int) int {
	if n < 1 {
		return 0
	}
	// Highest power of two strictly less than n
	return 1 << (bits.Len(uint(n-1)) - 1)
}

// merkleRoot computes the root of a subtree given its leaves.
func merkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		zero := sha256.Sum256(nil)
		return zero[:]
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left
			if i+1 < len(level) {
				right = level[i+1]
			}
			parent := MerkleNodeHash(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}
