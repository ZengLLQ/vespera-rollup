package test

import (
	"crypto/sha256"
	"math/big"
	"testing"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/mempool"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

func TestMempoolPriorityOrdering(t *testing.T) {
	pool := mempool.NewTxPool(100)
	sender := types.Address{0x10}

	tx1 := &types.Transaction{
		Nonce:     0,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(100),
	}
	tx2 := &types.Transaction{
		Nonce:     1,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(500),
	}

	if err := pool.AddTransaction(tx1, 0); err != nil {
		t.Fatalf("failed to add tx1: %v", err)
	}
	if err := pool.AddTransaction(tx2, 0); err != nil {
		t.Fatalf("failed to add tx2: %v", err)
	}

	pending := pool.GetPendingTransactions(10)
	if len(pending) != 2 {
		t.Fatalf("expected 2 pending transactions, got %d", len(pending))
	}
	// Nonce ordering for same sender must be preserved
	if pending[0].Nonce != 0 || pending[1].Nonce != 1 {
		t.Fatalf("nonce order violated: %d, %d", pending[0].Nonce, pending[1].Nonce)
	}
}

func TestMempoolReplacementRule(t *testing.T) {
	pool := mempool.NewTxPool(100)
	sender := types.Address{0x20}

	txOld := &types.Transaction{
		Nonce:     0,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(100),
	}
	if err := pool.AddTransaction(txOld, 0); err != nil {
		t.Fatalf("failed to add tx: %v", err)
	}

	// Replacement with <10% bump (105 vs 100 -> only 5% bump)
	txUnderpriced := &types.Transaction{
		Nonce:     0,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(105),
	}
	err := pool.AddTransaction(txUnderpriced, 0)
	if err != mempool.ErrUnderpriced {
		t.Fatalf("expected ErrUnderpriced, got: %v", err)
	}

	// Replacement with >=10% bump (115 vs 100 -> 15% bump)
	txValid := &types.Transaction{
		Nonce:     0,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(115),
	}
	if err := pool.AddTransaction(txValid, 0); err != nil {
		t.Fatalf("expected replacement to succeed, got: %v", err)
	}

	pending := pool.GetPendingTransactions(10)
	if len(pending) != 1 || pending[0].GasTipCap.Cmp(big.NewInt(115)) != 0 {
		t.Fatalf("expected replaced tx with tip 115, got %s", pending[0].GasTipCap.String())
	}
}

func TestMempoolCommitRevealMEV(t *testing.T) {
	pool := mempool.NewTxPool(100)
	sender := types.Address{0x30}

	tx := &types.Transaction{
		Nonce:     0,
		From:      sender,
		GasLimit:  21000,
		GasTipCap: big.NewInt(200),
	}

	txH := tx.Hash()
	commitHash := sha256.Sum256(txH[:])

	env := &mempool.EncryptedEnvelope{
		Commitment: types.Hash(commitHash),
		Sender:     sender,
		Timestamp:  time.Now(),
		Ciphertext: []byte("encrypted_payload"),
	}

	pool.CommitEnvelope(env)

	// Reveal
	if err := pool.RevealEnvelope(types.Hash(commitHash), tx, 0); err != nil {
		t.Fatalf("failed to reveal envelope: %v", err)
	}

	if pool.Size() != 1 {
		t.Fatalf("expected 1 admitted tx after reveal, got %d", pool.Size())
	}
}
