package scrapi

import (
	"crypto/sha256"
	"fmt"
	"math/bits"
	"os"

	"github.com/fxamacker/cbor/v2"
)

// RFC9162-style Merkle tree with optional persistence of leaf hashes.
type MerkleTree struct {
	leaves    [][]byte
	storePath string
}

// NewMerkleTree constructs a tree and, if storePath is non-empty, loads persisted leaves.
func NewMerkleTree(storePath string) *MerkleTree {
	t := &MerkleTree{storePath: storePath}
	if storePath != "" {
		_ = t.load()
	}
	return t
}

// Append adds a leaf and returns the leaf hash, root, inclusion proof, and size.
func (t *MerkleTree) Append(data []byte) (leaf []byte, root []byte, proof [][]byte, size int, err error) {
	leaf = merkleLeafHash(data)
	t.leaves = append(t.leaves, leaf)
	idx := len(t.leaves) - 1
	proof = t.inclusionProof(idx)
	root = t.currentRoot()
	size = len(t.leaves)
	if err = t.persist(); err != nil {
		return nil, nil, nil, 0, err
	}
	return leaf, root, proof, size, nil
}

// Root returns the current tree root.
func (t *MerkleTree) Root() []byte {
	return t.currentRoot()
}

// Size returns the number of leaves.
func (t *MerkleTree) Size() int {
	return len(t.leaves)
}

// ConsistencyProof returns an RFC6962/RFC9162 consistency proof between two sizes.
func (t *MerkleTree) ConsistencyProof(firstSize, secondSize int) ([][]byte, error) {
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
	return proof, nil
}

func (t *MerkleTree) inclusionProof(idx int) [][]byte {
	if idx < 0 || idx >= len(t.leaves) {
		return nil
	}
	proof := make([][]byte, 0, bits.Len(uint(len(t.leaves))))

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
			parent := merkleNodeHash(left, right)
			next = append(next, parent)

			if i == pos || i+1 == pos {
				if i+1 < len(level) {
					// sibling exists
					if i == pos {
						proof = append(proof, right)
					} else {
						proof = append(proof, left)
					}
				} else {
					// duplicated last node
					proof = append(proof, right)
				}
				pos = len(next) - 1
			}
		}
		level = next
	}
	return proof
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
			parent := merkleNodeHash(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}

func merkleLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	return h.Sum(nil)
}

func merkleNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// buildConsistencyProof implements RFC6962 section 2.1.2 for a slice of leaf hashes.
func buildConsistencyProof(leaves [][]byte, firstSize, secondSize int, proof *[][]byte) {
	if firstSize == secondSize {
		return
	}

	k := largestPowerOfTwoLessThan(secondSize)

	switch {
	case firstSize <= k:
		buildConsistencyProof(leaves[:k], firstSize, k, proof)
		*proof = append(*proof, merkleRoot(leaves[k:secondSize]))
	case firstSize > k:
		buildConsistencyProof(leaves[k:secondSize], firstSize-k, secondSize-k, proof)
		*proof = append(*proof, merkleRoot(leaves[:k]))
	}
}

func largestPowerOfTwoLessThan(n int) int {
	if n < 1 {
		return 0
	}
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
			parent := merkleNodeHash(left, right)
			next = append(next, parent)
		}
		level = next
	}
	return level[0]
}

func (t *MerkleTree) persist() error {
	if t.storePath == "" {
		return nil
	}
	data, err := cbor.Marshal(t.leaves)
	if err != nil {
		return err
	}
	return os.WriteFile(t.storePath, data, 0o644)
}

func (t *MerkleTree) load() error {
	data, err := os.ReadFile(t.storePath)
	if err != nil {
		return err
	}
	var leaves [][]byte
	if err := cbor.Unmarshal(data, &leaves); err != nil {
		return err
	}
	t.leaves = leaves
	return nil
}
