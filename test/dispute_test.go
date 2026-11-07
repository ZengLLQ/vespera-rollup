package test

import (
	"math/big"
	"testing"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/dispute"
	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

func TestBisectionDisputeGame(t *testing.T) {
	defender := types.Address{0xD1}
	challenger := types.Address{0xC1}
	bond := big.NewInt(1000)

	totalSteps := uint64(8)
	preState := crypto.HashUint64(0)
	postState := crypto.HashUint64(800)

	trace := make(map[uint64]types.Hash)
	trace[0] = preState
	for i := uint64(1); i <= totalSteps; i++ {
		trace[i] = crypto.HashUint64(i * 100)
	}

	game := dispute.NewBisectionGame(
		crypto.HashUint64(1),
		defender, challenger, bond,
		totalSteps, preState, postState,
		trace, 1*time.Hour,
	)

	// Bisect rounds
	// Step 1: Challenger disputes midpoint 4 (disagrees with 4 -> search [0, 4])
	_, _, err := game.Bisect(challenger, false)
	if err != nil {
		t.Fatalf("bisect step 1 failed: %v", err)
	}
	if game.LeftIndex != 0 || game.RightIndex != 4 {
		t.Fatalf("expected [0, 4], got [%d, %d]", game.LeftIndex, game.RightIndex)
	}

	// Step 2: Defender responds (agrees with midpoint 2 -> search [2, 4])
	_, _, err = game.Bisect(defender, true)
	if err != nil {
		t.Fatalf("bisect step 2 failed: %v", err)
	}
	if game.LeftIndex != 2 || game.RightIndex != 4 {
		t.Fatalf("expected [2, 4], got [%d, %d]", game.LeftIndex, game.RightIndex)
	}

	// Step 3: Challenger responds (disagrees with midpoint 3 -> search [2, 3])
	_, _, err = game.Bisect(challenger, false)
	if err != nil {
		t.Fatalf("bisect step 3 failed: %v", err)
	}
	if game.LeftIndex != 2 || game.RightIndex != 3 {
		t.Fatalf("expected [2, 3], got [%d, %d]", game.LeftIndex, game.RightIndex)
	}

	if !game.IsReadyForSingleStepResolution() {
		t.Fatal("game should be ready for single step resolution (Right - Left == 1)")
	}
}

func TestSingleStepFraudResolution(t *testing.T) {
	ws := state.NewWorldState()
	from := types.Address{0xAA}
	to := types.Address{0xBB}
	ws.SetBalance(from, big.NewInt(1000000000000000))

	preRoot := ws.Commit()

	tx := &types.Transaction{
		Type:      types.TxTypeLegacy,
		Nonce:     0,
		From:      from,
		To:        &to,
		Value:     big.NewInt(500),
		GasLimit:  21000,
		GasFeeCap: big.NewInt(1000000000),
	}

	// Compute real post state
	wsPost := state.NewWorldState()
	wsPost.SetBalance(from, big.NewInt(1000000000000000))
	gasPool := uint64(30000000)
	header := &types.Header{
		Number:   1,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1000000000),
	}
	_, _ = state.ApplyTransaction(wsPost, tx, header, &gasPool, types.Address{0x01})
	realPostRoot := wsPost.Commit()

	verifier := dispute.NewSingleStepVerifier()

	// 1. Truthful witness test
	truthfulWitness := &dispute.StepWitness{
		StepIndex:     0,
		PreStateRoot:  preRoot,
		PostStateRoot: realPostRoot,
		Transaction:   tx,
		HeaderContext: header,
		PreStateBalances: map[types.Address]*big.Int{
			from: big.NewInt(1000000000000000),
		},
		PreStateNonces: map[types.Address]uint64{
			from: 0,
		},
	}
	valid, _, err := verifier.VerifyStep(truthfulWitness, types.Address{0x01})
	if err != nil || !valid {
		t.Fatalf("expected valid step for truthful witness: %v", err)
	}

	// 2. Fraudulent witness test (tampered post state root)
	fraudulentWitness := &dispute.StepWitness{
		StepIndex:     0,
		PreStateRoot:  preRoot,
		PostStateRoot: crypto.HashUint64(0xDEADBEEF),
		Transaction:   tx,
		HeaderContext: header,
		PreStateBalances: map[types.Address]*big.Int{
			from: big.NewInt(1000000000000000),
		},
		PreStateNonces: map[types.Address]uint64{
			from: 0,
		},
	}
	valid, _, err = verifier.VerifyStep(fraudulentWitness, types.Address{0x01})
	if err != nil {
		t.Fatalf("unexpected execution error: %v", err)
	}
	if valid {
		t.Fatal("expected fraudulent witness to fail verification")
	}
}
