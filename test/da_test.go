package test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/ZengLLQ/vespera-rollup/pkg/da"
)

func TestReedSolomonReconstruction(t *testing.T) {
	k := 4
	p := 4
	total := k + p
	shardSize := 128

	rs, err := da.NewReedSolomon(k, p)
	if err != nil {
		t.Fatalf("failed to create RS: %v", err)
	}

	shards := make([][]byte, total)
	originalData := make([][]byte, k)
	for i := 0; i < k; i++ {
		shards[i] = make([]byte, shardSize)
		rand.Read(shards[i])
		originalData[i] = append([]byte(nil), shards[i]...)
	}
	for i := k; i < total; i++ {
		shards[i] = make([]byte, shardSize)
	}

	// Encode parity shards
	if err := rs.Encode(shards); err != nil {
		t.Fatalf("failed to encode: %v", err)
	}

	// Simulate losing 2 data shards (e.g. shards 1 and 3)
	present := make([]bool, total)
	for i := range present {
		present[i] = true
	}
	shards[1] = nil
	present[1] = false
	shards[3] = nil
	present[3] = false

	// Reconstruct
	if err := rs.Reconstruct(shards, present); err != nil {
		t.Fatalf("reconstruction failed: %v", err)
	}

	// Verify byte-for-byte exact match with original data
	for i := 0; i < k; i++ {
		if !bytes.Equal(shards[i], originalData[i]) {
			t.Fatalf("shard %d mismatch after reconstruction", i)
		}
	}
}

func Test2DMatrixDataAvailabilitySampling(t *testing.T) {
	k := 4
	shardSize := 32
	data := make([][]byte, k*k)
	for i := range data {
		data[i] = make([]byte, shardSize)
		rand.Read(data[i])
	}

	matrix, err := da.Encode2DMatrix(data, k, shardSize)
	if err != nil {
		t.Fatalf("failed to encode 2D matrix: %v", err)
	}

	if len(matrix.RowRoots) != 2*k || len(matrix.ColRoots) != 2*k {
		t.Fatalf("incorrect root counts: rows=%d, cols=%d", len(matrix.RowRoots), len(matrix.ColRoots))
	}

	// Test sampling
	samples, err := matrix.Sample(15)
	if err != nil {
		t.Fatalf("failed to sample: %v", err)
	}

	for _, s := range samples {
		if !da.VerifySample(s) {
			t.Fatalf("sample at row %d, col %d failed verification", s.Row, s.Col)
		}
	}
}
