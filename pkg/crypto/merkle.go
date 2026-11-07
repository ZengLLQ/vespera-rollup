package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sync"

	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

const TreeDepth = 256

// HashPair computes H(left || right).
func HashPair(left, right types.Hash) types.Hash {
	h := sha256.New()
	h.Write(left[:])
	h.Write(right[:])
	var res types.Hash
	copy(res[:], h.Sum(nil))
	return res
}

// HashLeaf computes H(0x00 || key || value).
func HashLeaf(key, value types.Hash) types.Hash {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(key[:])
	h.Write(value[:])
	var res types.Hash
	copy(res[:], h.Sum(nil))
	return res
}

// SparseMerkleTree maintains a 256-bit Sparse Merkle Tree for state commitments.
type SparseMerkleTree struct {
	mu          sync.RWMutex
	root        types.Hash
	levels      [TreeDepth]map[types.Hash]types.Hash
	leaves      map[types.Hash]types.Hash // key -> value
	emptyHashes [TreeDepth + 1]types.Hash
}

func NewSparseMerkleTree() *SparseMerkleTree {
	smt := &SparseMerkleTree{
		leaves: make(map[types.Hash]types.Hash),
	}
	for d := 0; d < TreeDepth; d++ {
		smt.levels[d] = make(map[types.Hash]types.Hash)
	}
	// Precompute default empty hashes: emptyHashes[0] = 0x00...00
	smt.emptyHashes[0] = types.EmptyHash
	for d := 0; d < TreeDepth; d++ {
		smt.emptyHashes[d+1] = HashPair(smt.emptyHashes[d], smt.emptyHashes[d])
	}
	smt.root = smt.emptyHashes[TreeDepth]
	return smt
}

func (smt *SparseMerkleTree) Root() types.Hash {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	return smt.root
}

// Update updates or inserts a key-value pair and recomputes the root.
func (smt *SparseMerkleTree) Update(key, value types.Hash) types.Hash {
	smt.mu.Lock()
	defer smt.mu.Unlock()

	if value.IsZero() {
		delete(smt.leaves, key)
	} else {
		smt.leaves[key] = value
	}

	smt.root = smt.recomputeRoot()
	return smt.root
}

// Get retrieves the value for a given key.
func (smt *SparseMerkleTree) Get(key types.Hash) (types.Hash, bool) {
	smt.mu.RLock()
	defer smt.mu.RUnlock()
	val, ok := smt.leaves[key]
	return val, ok
}

// recomputeRoot computes the deterministic SMT root from all leaves.
func (smt *SparseMerkleTree) recomputeRoot() types.Hash {
	for d := 0; d < TreeDepth; d++ {
		smt.levels[d] = make(map[types.Hash]types.Hash)
	}

	if len(smt.leaves) == 0 {
		return smt.emptyHashes[TreeDepth]
	}

	// Build compact tree from active leaves
	currentLevel := make(map[types.Hash]types.Hash)
	for k, v := range smt.leaves {
		currentLevel[k] = HashLeaf(k, v)
	}
	smt.levels[0] = currentLevel

	for d := 0; d < TreeDepth; d++ {
		nextLevel := make(map[types.Hash]types.Hash)
		processedPairs := make(map[types.Hash]bool)

		for key, hash := range currentLevel {
			siblingKey := flipBit(key, d)
			pairKey := minKey(key, siblingKey)
			if processedPairs[pairKey] {
				continue
			}
			processedPairs[pairKey] = true

			siblingHash, hasSibling := currentLevel[siblingKey]
			if !hasSibling {
				siblingHash = smt.emptyHashes[d]
			}

			var parentHash types.Hash
			if getBit(key, d) == 0 {
				parentHash = HashPair(hash, siblingHash)
			} else {
				parentHash = HashPair(siblingHash, hash)
			}

			parentKey := clearBit(key, d)
			nextLevel[parentKey] = parentHash
		}
		if d+1 < TreeDepth {
			smt.levels[d+1] = nextLevel
		}
		currentLevel = nextLevel
		if len(currentLevel) == 1 && d < TreeDepth-1 {
			var remainingKey, remainingHash types.Hash
			for k, v := range currentLevel {
				remainingKey, remainingHash = k, v
			}
			return smt.fastForwardRoot(remainingKey, remainingHash, d+1)
		}
	}

	for _, root := range currentLevel {
		return root
	}
	return smt.emptyHashes[TreeDepth]
}

func (smt *SparseMerkleTree) fastForwardRoot(key types.Hash, hash types.Hash, fromDepth int) types.Hash {
	curr := hash
	currKey := key
	for d := fromDepth; d < TreeDepth; d++ {
		if smt.levels[d] == nil {
			smt.levels[d] = make(map[types.Hash]types.Hash)
		}
		smt.levels[d][currKey] = curr

		empty := smt.emptyHashes[d]
		if getBit(currKey, d) == 0 {
			curr = HashPair(curr, empty)
		} else {
			curr = HashPair(empty, curr)
		}
		currKey = clearBit(currKey, d)
	}
	return curr
}

// Proof contains sibling hashes along the path from leaf to root.
type Proof struct {
	Key      types.Hash
	Value    types.Hash
	Siblings []types.Hash
	Depth    int
}

// GenerateProof produces an inclusion proof for the specified key.
func (smt *SparseMerkleTree) GenerateProof(key types.Hash) (*Proof, error) {
	smt.mu.RLock()
	defer smt.mu.RUnlock()

	val := smt.leaves[key]
	siblings := make([]types.Hash, TreeDepth)

	currKey := key
	for d := 0; d < TreeDepth; d++ {
		sibKey := flipBit(currKey, d)
		if lvl := smt.levels[d]; lvl != nil {
			if sibHash, ok := lvl[sibKey]; ok {
				siblings[d] = sibHash
			} else {
				siblings[d] = smt.emptyHashes[d]
			}
		} else {
			siblings[d] = smt.emptyHashes[d]
		}
		currKey = clearBit(currKey, d)
	}

	return &Proof{
		Key:      key,
		Value:    val,
		Siblings: siblings,
		Depth:    len(siblings),
	}, nil
}

// VerifyProof verifies that key-value pair evaluates to the expected root.
func VerifyProof(root types.Hash, key, value types.Hash, siblings []types.Hash) bool {
	var current types.Hash
	if value.IsZero() {
		current = types.EmptyHash
	} else {
		current = HashLeaf(key, value)
	}

	for d, sibling := range siblings {
		bit := getBit(key, d)
		if bit == 0 {
			current = HashPair(current, sibling)
		} else {
			current = HashPair(sibling, current)
		}
	}

	return bytes.Equal(current[:], root[:])
}

// Bit manipulation helpers for 256-bit hashes
func getBit(h types.Hash, bitIndex int) byte {
	byteIdx := bitIndex / 8
	bitOffset := uint(7 - (bitIndex % 8))
	if byteIdx >= 32 {
		return 0
	}
	return (h[byteIdx] >> bitOffset) & 1
}

func flipBit(h types.Hash, bitIndex int) types.Hash {
	res := h
	byteIdx := bitIndex / 8
	bitOffset := uint(7 - (bitIndex % 8))
	if byteIdx < 32 {
		res[byteIdx] ^= (1 << bitOffset)
	}
	return res
}

func clearBit(h types.Hash, bitIndex int) types.Hash {
	res := h
	byteIdx := bitIndex / 8
	bitOffset := uint(7 - (bitIndex % 8))
	if byteIdx < 32 {
		res[byteIdx] &= ^(1 << bitOffset)
	}
	return res
}

func minKey(a, b types.Hash) types.Hash {
	if bytes.Compare(a[:], b[:]) <= 0 {
		return a
	}
	return b
}

// ComputeTxRoot calculates standard Merkle root of transactions.
func ComputeTxRoot(txs []*types.Transaction) types.Hash {
	if len(txs) == 0 {
		return types.EmptyHash
	}
	hashes := make([]types.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash()
	}
	return computeMerkleRoot(hashes)
}

func computeMerkleRoot(hashes []types.Hash) types.Hash {
	if len(hashes) == 0 {
		return types.EmptyHash
	}
	if len(hashes) == 1 {
		return hashes[0]
	}
	var nextLevel []types.Hash
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			nextLevel = append(nextLevel, HashPair(hashes[i], hashes[i+1]))
		} else {
			nextLevel = append(nextLevel, HashPair(hashes[i], hashes[i]))
		}
	}
	return computeMerkleRoot(nextLevel)
}

func HashUint64(n uint64) types.Hash {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, n)
	var res types.Hash
	copy(res[:], h.Sum(nil))
	return res
}
