package test

import (
	"math/big"
	"testing"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

func TestSparseMerkleTree(t *testing.T) {
	smt := crypto.NewSparseMerkleTree()
	initialRoot := smt.Root()

	k1 := crypto.HashUint64(100)
	v1 := crypto.HashUint64(200)

	root1 := smt.Update(k1, v1)
	if root1 == initialRoot {
		t.Fatal("root should change after inserting key")
	}

	val, found := smt.Get(k1)
	if !found || val != v1 {
		t.Fatalf("expected value %x, got %x", v1, val)
	}

	// Inclusion proof
	proof, err := smt.GenerateProof(k1)
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}
	if !crypto.VerifyProof(root1, k1, v1, proof.Siblings) {
		t.Fatal("proof verification failed")
	}
}

func TestWorldStateSnapshotRevert(t *testing.T) {
	ws := state.NewWorldState()
	addr := types.Address{0x01}
	bal := big.NewInt(1000)

	ws.SetBalance(addr, bal)
	ws.SetNonce(addr, 5)

	snap := ws.Snapshot()

	// Mutate state
	ws.SetBalance(addr, big.NewInt(2500))
	ws.SetNonce(addr, 6)

	if ws.GetBalance(addr).Cmp(big.NewInt(2500)) != 0 {
		t.Fatal("balance did not update")
	}

	// Revert
	ws.RevertToSnapshot(snap)

	if ws.GetBalance(addr).Cmp(bal) != 0 {
		t.Fatalf("revert failed, expected balance %s, got %s", bal.String(), ws.GetBalance(addr).String())
	}
	if ws.GetNonce(addr) != 5 {
		t.Fatalf("revert failed, expected nonce 5, got %d", ws.GetNonce(addr))
	}
}

func TestEIP1559BaseFeeAdjustment(t *testing.T) {
	parent := &types.Header{
		GasLimit: 30000000,
		GasUsed:  15000000, // Exactly target (30M / 2)
		BaseFee:  big.NewInt(1000000000),
	}

	// Equal to target -> fee unchanged
	nextFee := state.CalculateBaseFee(parent)
	if nextFee.Cmp(parent.BaseFee) != 0 {
		t.Fatalf("expected unchanged base fee, got %s", nextFee.String())
	}

	// Higher than target -> fee increases
	parent.GasUsed = 30000000 // Full block
	nextFeeHigher := state.CalculateBaseFee(parent)
	if nextFeeHigher.Cmp(parent.BaseFee) <= 0 {
		t.Fatal("base fee should increase when gas used exceeds target")
	}

	// Lower than target -> fee decreases
	parent.GasUsed = 0 // Empty block
	nextFeeLower := state.CalculateBaseFee(parent)
	if nextFeeLower.Cmp(parent.BaseFee) >= 0 {
		t.Fatal("base fee should decrease when gas used is below target")
	}
}

func TestApplyTransaction(t *testing.T) {
	ws := state.NewWorldState()
	from := types.Address{0xAA}
	to := types.Address{0xBB}
	seq := types.Address{0x01}

	// Fund sender with 5 ETH
	ws.SetBalance(from, new(big.Int).Mul(big.NewInt(5), big.NewInt(1e18)))

	header := &types.Header{
		Number:   1,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1000000000), // 1 Gwei
	}
	gasRemaining := header.GasLimit

	tx := &types.Transaction{
		Type:      types.TxTypeEIP1559,
		Nonce:     0,
		From:      from,
		To:        &to,
		Value:     big.NewInt(1e18),       // 1 ETH
		GasLimit:  21000,
		GasFeeCap: big.NewInt(2000000000), // 2 Gwei
		GasTipCap: big.NewInt(500000000),  // 0.5 Gwei tip
	}

	receipt, err := state.ApplyTransaction(ws, tx, header, &gasRemaining, seq)
	if err != nil {
		t.Fatalf("failed to apply transaction: %v", err)
	}

	if receipt.Status != 1 {
		t.Fatalf("transaction status failed: %d", receipt.Status)
	}

	// Check balances
	if ws.GetBalance(to).Cmp(big.NewInt(1e18)) != 0 {
		t.Fatalf("recipient balance incorrect: %s", ws.GetBalance(to).String())
	}
	if ws.GetNonce(from) != 1 {
		t.Fatalf("expected nonce 1, got %d", ws.GetNonce(from))
	}
	if ws.GetBalance(seq).Sign() <= 0 {
		t.Fatal("sequencer should receive priority tip")
	}
}
