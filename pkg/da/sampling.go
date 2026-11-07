package da

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

// ExtendedMatrix represents a 2D Reed-Solomon extended data availability block.
type ExtendedMatrix struct {
	OriginalSize int        // K
	ExtendedSize int        // 2K
	ShardSize    int        // bytes per cell
	Grid         [][][]byte // [row][col][byte]
	RowRoots     []types.Hash
	ColRoots     []types.Hash
	DataRoot     types.Hash // Merkle root of row roots + col roots
}

// SampleShare represents a queried cell in the 2D DA grid with verification proofs.
type SampleShare struct {
	Row       int
	Col       int
	Data      []byte
	RowProof  []types.Hash
	ColProof  []types.Hash
	RowRoot   types.Hash
	ColRoot   types.Hash
}

// Encode2DMatrix encodes K×K data shards into 2K×2K extended matrix.
func Encode2DMatrix(data [][]byte, k int, shardSize int) (*ExtendedMatrix, error) {
	if len(data) != k*k {
		return nil, fmt.Errorf("expected %d shards for %d×%d grid, got %d", k*k, k, k, len(data))
	}
	rs, err := NewReedSolomon(k, k)
	if err != nil {
		return nil, err
	}

	extendedSize := 2 * k
	grid := make([][][]byte, extendedSize)
	for r := 0; r < extendedSize; r++ {
		grid[r] = make([][]byte, extendedSize)
	}

	// 1. Populate top-left K×K grid
	for r := 0; r < k; r++ {
		for c := 0; c < k; c++ {
			grid[r][c] = make([]byte, shardSize)
			copy(grid[r][c], data[r*k+c])
		}
	}

	// 2. Horizontally encode first K rows (K -> 2K)
	for r := 0; r < k; r++ {
		rowShards := make([][]byte, extendedSize)
		for c := 0; c < k; c++ {
			rowShards[c] = grid[r][c]
		}
		for c := k; c < extendedSize; c++ {
			rowShards[c] = make([]byte, shardSize)
		}
		if err := rs.Encode(rowShards); err != nil {
			return nil, err
		}
		for c := k; c < extendedSize; c++ {
			grid[r][c] = rowShards[c]
		}
	}

	// 3. Vertically encode all 2K columns (K -> 2K)
	for c := 0; c < extendedSize; c++ {
		colShards := make([][]byte, extendedSize)
		for r := 0; r < k; r++ {
			colShards[r] = grid[r][c]
		}
		for r := k; r < extendedSize; r++ {
			colShards[r] = make([]byte, shardSize)
		}
		if err := rs.Encode(colShards); err != nil {
			return nil, err
		}
		for r := k; r < extendedSize; r++ {
			grid[r][c] = colShards[r]
		}
	}

	// 4. Compute row and column Merkle roots
	rowRoots := make([]types.Hash, extendedSize)
	for r := 0; r < extendedSize; r++ {
		rowHashes := make([]types.Hash, extendedSize)
		for c := 0; c < extendedSize; c++ {
			h := sha256.Sum256(grid[r][c])
			rowHashes[c] = types.Hash(h)
		}
		rowRoots[r] = computeSimpleMerkle(rowHashes)
	}

	colRoots := make([]types.Hash, extendedSize)
	for c := 0; c < extendedSize; c++ {
		colHashes := make([]types.Hash, extendedSize)
		for r := 0; r < extendedSize; r++ {
			h := sha256.Sum256(grid[r][c])
			colHashes[r] = types.Hash(h)
		}
		colRoots[c] = computeSimpleMerkle(colHashes)
	}

	// Combined data root: Merkle root of (RowRoots || ColRoots)
	allRoots := append(rowRoots, colRoots...)
	dataRoot := computeSimpleMerkle(allRoots)

	return &ExtendedMatrix{
		OriginalSize: k,
		ExtendedSize: extendedSize,
		ShardSize:    shardSize,
		Grid:         grid,
		RowRoots:     rowRoots,
		ColRoots:     colRoots,
		DataRoot:     dataRoot,
	}, nil
}

// Sample randomly queries sampleCount cells across the 2D grid.
func (em *ExtendedMatrix) Sample(sampleCount int) ([]*SampleShare, error) {
	samples := make([]*SampleShare, sampleCount)
	for i := 0; i < sampleCount; i++ {
		rBig, _ := rand.Int(rand.Reader, big.NewInt(int64(em.ExtendedSize)))
		cBig, _ := rand.Int(rand.Reader, big.NewInt(int64(em.ExtendedSize)))
		r := int(rBig.Int64())
		c := int(cBig.Int64())

		rowHashes := make([]types.Hash, em.ExtendedSize)
		for j := 0; j < em.ExtendedSize; j++ {
			h := sha256.Sum256(em.Grid[r][j])
			rowHashes[j] = types.Hash(h)
		}
		rowProof := generateSimpleProof(rowHashes, c)

		colHashes := make([]types.Hash, em.ExtendedSize)
		for j := 0; j < em.ExtendedSize; j++ {
			h := sha256.Sum256(em.Grid[j][c])
			colHashes[j] = types.Hash(h)
		}
		colProof := generateSimpleProof(colHashes, r)

		samples[i] = &SampleShare{
			Row:      r,
			Col:      c,
			Data:     append([]byte(nil), em.Grid[r][c]...),
			RowProof: rowProof,
			ColProof: colProof,
			RowRoot:  em.RowRoots[r],
			ColRoot:  em.ColRoots[c],
		}
	}
	return samples, nil
}

// VerifySample confirms the integrity of a sampled share against its row root.
func VerifySample(sample *SampleShare) bool {
	leaf := types.Hash(sha256.Sum256(sample.Data))
	return verifySimpleProof(sample.RowRoot, leaf, sample.Col, sample.RowProof)
}

func computeSimpleMerkle(leaves []types.Hash) types.Hash {
	if len(leaves) == 0 {
		return types.EmptyHash
	}
	if len(leaves) == 1 {
		return leaves[0]
	}
	var nextLevel []types.Hash
	for i := 0; i < len(leaves); i += 2 {
		if i+1 < len(leaves) {
			nextLevel = append(nextLevel, crypto.HashPair(leaves[i], leaves[i+1]))
		} else {
			nextLevel = append(nextLevel, crypto.HashPair(leaves[i], leaves[i]))
		}
	}
	return computeSimpleMerkle(nextLevel)
}

func generateSimpleProof(leaves []types.Hash, targetIndex int) []types.Hash {
	var proof []types.Hash
	current := leaves
	idx := targetIndex

	for len(current) > 1 {
		var next []types.Hash
		siblingIdx := idx ^ 1
		if siblingIdx < len(current) {
			proof = append(proof, current[siblingIdx])
		} else {
			proof = append(proof, current[idx])
		}

		for i := 0; i < len(current); i += 2 {
			if i+1 < len(current) {
				next = append(next, crypto.HashPair(current[i], current[i+1]))
			} else {
				next = append(next, crypto.HashPair(current[i], current[i]))
			}
		}
		idx /= 2
		current = next
	}

	return proof
}

func verifySimpleProof(root types.Hash, leaf types.Hash, index int, proof []types.Hash) bool {
	curr := leaf
	idx := index
	for _, sibling := range proof {
		if idx%2 == 0 {
			curr = crypto.HashPair(curr, sibling)
		} else {
			curr = crypto.HashPair(sibling, curr)
		}
		idx /= 2
	}
	return curr == root
}
