package test

import (
	"math/big"
	"testing"

	"github.com/ZengLLQ/vespera-rollup/pkg/mempool"
	"github.com/ZengLLQ/vespera-rollup/pkg/sequencer"
	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

func TestDerivationPipeline(t *testing.T) {
	wsSeq := state.NewWorldState()
	pool := mempool.NewTxPool(100)
	seqAddr := types.Address{0x01}
	user := types.Address{0xAA}

	wsSeq.SetBalance(user, big.NewInt(1000000000000000000))
	seq := sequencer.NewRollupSequencer(seqAddr, wsSeq, pool, 2, 30000000)

	// Produce 2 blocks
	blk1, err := seq.ProduceBlock(10)
	if err != nil {
		t.Fatalf("failed to produce blk1: %v", err)
	}
	blk2, err := seq.ProduceBlock(10)
	if err != nil {
		t.Fatalf("failed to produce blk2: %v", err)
	}

	batch, err := seq.CreateBatch([]*types.Block{blk1, blk2})
	if err != nil {
		t.Fatalf("failed to create batch: %v", err)
	}
	if len(batch.Blocks) != 2 {
		t.Fatalf("expected 2 blocks in batch, got %d", len(batch.Blocks))
	}

	// Create Derivation Pipeline
	wsDerive := state.NewWorldState()
	wsDerive.SetBalance(user, big.NewInt(1000000000000000000))
	dp := sequencer.NewDerivationPipeline(seq.LatestBlock(), wsDerive, 5)

	// Test Enqueue Deposit
	dp.EnqueueL1Deposit(types.Address{0xDE}, user, big.NewInt(500), 100000, nil)
	if dp.PendingDepositCount() != 1 {
		t.Fatalf("expected 1 pending deposit, got %d", dp.PendingDepositCount())
	}

	// Test L1 Reorg handling
	err = dp.HandleL1Reorg(0) // No-op
	if err != nil {
		t.Fatalf("reorg 0 should succeed: %v", err)
	}

	head := dp.CanonicalHead()
	if head.Hash() != seq.LatestBlock().Hash() {
		t.Fatal("canonical head mismatch")
	}
}
