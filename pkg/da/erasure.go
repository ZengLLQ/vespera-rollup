package da

import (
	"errors"
	"fmt"
)

// GF(2^8) Galois Field implementation with primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1)
var (
	gfExp [512]byte
	gfLog [256]byte
)

func init() {
	var x byte = 1
	for i := 0; i < 255; i++ {
		gfExp[i] = x
		gfExp[i+255] = x
		gfLog[x] = byte(i)
		// Multiply by 2: if high bit is set, XOR with 0x11d
		if x&0x80 != 0 {
			x = (x << 1) ^ 0x1d
		} else {
			x <<= 1
		}
	}
	gfLog[0] = 0 // log(0) is mathematically undefined, sentinel
}

// gfMul multiplies two elements in GF(2^8).
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// gfInv computes multiplicative inverse a^-1 in GF(2^8).
func gfInv(a byte) byte {
	if a == 0 {
		panic("division by zero in GF(2^8)")
	}
	return gfExp[255-int(gfLog[a])]
}

// gfDiv divides a by b in GF(2^8).
func gfDiv(a, b byte) byte {
	if b == 0 {
		panic("division by zero in GF(2^8)")
	}
	if a == 0 {
		return 0
	}
	logDiff := int(gfLog[a]) - int(gfLog[b])
	if logDiff < 0 {
		logDiff += 255
	}
	return gfExp[logDiff]
}

// ReedSolomon implements systematic (K, N) Cauchy Reed-Solomon coding.
type ReedSolomon struct {
	DataShards   int
	ParityShards int
	TotalShards  int
	Matrix       [][]byte // Cauchy generator matrix: (TotalShards × DataShards)
}

// NewReedSolomon creates an encoder with K data shards and P parity shards.
func NewReedSolomon(dataShards, parityShards int) (*ReedSolomon, error) {
	if dataShards <= 0 || parityShards <= 0 {
		return nil, errors.New("shard counts must be positive")
	}
	totalShards := dataShards + parityShards
	if totalShards > 256 {
		return nil, fmt.Errorf("total shards %d exceeds GF(2^8) field size 256", totalShards)
	}

	// Build Cauchy matrix:
	// Top K rows = Identity matrix I_K
	// Bottom P rows = Cauchy matrix C_{i, j} = 1 / (X_i ^ Y_j)
	// where X_i = dataShards + i, Y_j = j
	matrix := make([][]byte, totalShards)
	for i := 0; i < dataShards; i++ {
		row := make([]byte, dataShards)
		row[i] = 1
		matrix[i] = row
	}

	for i := 0; i < parityShards; i++ {
		row := make([]byte, dataShards)
		xi := byte(dataShards + i)
		for j := 0; j < dataShards; j++ {
			yj := byte(j)
			diff := xi ^ yj
			row[j] = gfInv(diff)
		}
		matrix[dataShards+i] = row
	}

	return &ReedSolomon{
		DataShards:   dataShards,
		ParityShards: parityShards,
		TotalShards:  totalShards,
		Matrix:       matrix,
	}, nil
}

// Encode generates parity shards from data shards.
func (rs *ReedSolomon) Encode(shards [][]byte) error {
	if len(shards) != rs.TotalShards {
		return fmt.Errorf("expected %d shards, got %d", rs.TotalShards, len(shards))
	}
	shardSize := len(shards[0])

	for p := 0; p < rs.ParityShards; p++ {
		parityIdx := rs.DataShards + p
		if shards[parityIdx] == nil {
			shards[parityIdx] = make([]byte, shardSize)
		} else {
			for b := range shards[parityIdx] {
				shards[parityIdx][b] = 0
			}
		}

		coeffRow := rs.Matrix[parityIdx]
		for d := 0; d < rs.DataShards; d++ {
			c := coeffRow[d]
			dataShard := shards[d]
			for b := 0; b < shardSize; b++ {
				shards[parityIdx][b] ^= gfMul(c, dataShard[b])
			}
		}
	}

	return nil
}

// Reconstruct recovers missing data shards from any subset of DataShards available shards.
func (rs *ReedSolomon) Reconstruct(shards [][]byte, present []bool) error {
	if len(shards) != rs.TotalShards || len(present) != rs.TotalShards {
		return errors.New("invalid shard slice lengths")
	}

	availableCount := 0
	for _, p := range present {
		if p {
			availableCount++
		}
	}
	if availableCount < rs.DataShards {
		return fmt.Errorf("cannot reconstruct: only %d shards available, need %d", availableCount, rs.DataShards)
	}

	// Check if all data shards are already present
	allDataPresent := true
	for i := 0; i < rs.DataShards; i++ {
		if !present[i] {
			allDataPresent = false
			break
		}
	}
	if allDataPresent {
		return nil
	}

	shardSize := 0
	for i, p := range present {
		if p && shards[i] != nil {
			shardSize = len(shards[i])
			break
		}
	}

	// Select first K available shards to build K×K submatrix
	subMatrix := make([][]byte, rs.DataShards)
	subShards := make([][]byte, rs.DataShards)
	selected := 0

	for i := 0; i < rs.TotalShards && selected < rs.DataShards; i++ {
		if present[i] {
			subMatrix[selected] = make([]byte, rs.DataShards)
			copy(subMatrix[selected], rs.Matrix[i])
			subShards[selected] = shards[i]
			selected++
		}
	}

	// Invert the K×K submatrix using Gaussian elimination
	invMatrix, err := invertMatrix(subMatrix)
	if err != nil {
		return fmt.Errorf("matrix inversion failed: %w", err)
	}

	// Multiply invMatrix with subShards to recover original K data shards
	for d := 0; d < rs.DataShards; d++ {
		if !present[d] {
			if shards[d] == nil {
				shards[d] = make([]byte, shardSize)
			}
			for j := 0; j < rs.DataShards; j++ {
				coeff := invMatrix[d][j]
				for b := 0; b < shardSize; b++ {
					shards[d][b] ^= gfMul(coeff, subShards[j][b])
				}
			}
			present[d] = true
		}
	}

	return nil
}

// invertMatrix inverts a square matrix over GF(2^8) via Gauss-Jordan elimination.
func invertMatrix(matrix [][]byte) ([][]byte, error) {
	n := len(matrix)
	aug := make([][]byte, n)
	for i := 0; i < n; i++ {
		aug[i] = make([]byte, 2*n)
		copy(aug[i][:n], matrix[i])
		aug[i][n+i] = 1 // Identity on right
	}

	for col := 0; col < n; col++ {
		// Find pivot
		pivotRow := -1
		for r := col; r < n; r++ {
			if aug[r][col] != 0 {
				pivotRow = r
				break
			}
		}
		if pivotRow == -1 {
			return nil, errors.New("singular matrix")
		}

		// Swap rows
		aug[col], aug[pivotRow] = aug[pivotRow], aug[col]

		// Scale pivot row so leading entry is 1
		invPivot := gfInv(aug[col][col])
		for j := col; j < 2*n; j++ {
			aug[col][j] = gfMul(aug[col][j], invPivot)
		}

		// Eliminate column in all other rows
		for r := 0; r < n; r++ {
			if r != col && aug[r][col] != 0 {
				factor := aug[r][col]
				for j := col; j < 2*n; j++ {
					aug[r][j] ^= gfMul(factor, aug[col][j])
				}
			}
		}
	}

	inv := make([][]byte, n)
	for i := 0; i < n; i++ {
		inv[i] = make([]byte, n)
		copy(inv[i], aug[i][n:])
	}
	return inv, nil
}
