package dispute

import (
	"crypto/sha256"
	"errors"
	"math/big"

	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

// StepWitness encapsulates the exact pre-state and transaction inputs to verify a single transition.
type StepWitness struct {
	StepIndex        uint64             `json:"step_index"`
	PreStateRoot     types.Hash         `json:"pre_state_root"`
	PostStateRoot    types.Hash         `json:"post_state_root"`
	Transaction      *types.Transaction `json:"transaction"`
	HeaderContext    *types.Header      `json:"header_context"`
	PreStateBalances map[types.Address]*big.Int `json:"pre_state_balances"`
	PreStateNonces   map[types.Address]uint64   `json:"pre_state_nonces"`
}

// SingleStepVerifier deterministically executes one transaction to confirm or refute fraud.
type SingleStepVerifier struct{}

func NewSingleStepVerifier() *SingleStepVerifier {
	return &SingleStepVerifier{}
}

// VerifyStep executes the transaction on the pre-state and asserts whether the claimed post-state is valid.
func (v *SingleStepVerifier) VerifyStep(witness *StepWitness, sequencerAddr types.Address) (bool, types.Hash, error) {
	if witness.Transaction == nil {
		return false, types.EmptyHash, errors.New("nil transaction in witness")
	}

	// Reconstruct local world state from witness balances & nonces
	ws := state.NewWorldState()
	for addr, bal := range witness.PreStateBalances {
		ws.SetBalance(addr, bal)
	}
	for addr, nonce := range witness.PreStateNonces {
		ws.SetNonce(addr, nonce)
	}

	preRoot := ws.Commit()
	if preRoot != witness.PreStateRoot {
		return false, preRoot, errors.New("witness pre-state does not match claimed PreStateRoot")
	}

	// Execute transaction
	gasPool := witness.HeaderContext.GasLimit
	_, err := state.ApplyTransaction(ws, witness.Transaction, witness.HeaderContext, &gasPool, sequencerAddr)
	if err != nil {
		// Even if transaction fails, state advances (nonce + gas fee)
	}

	actualPostRoot := ws.Commit()
	isValid := (actualPostRoot == witness.PostStateRoot)

	return isValid, actualPostRoot, nil
}

// HashStep produces a canonical fingerprint of a step state.
func HashStep(step uint64, stateRoot types.Hash) types.Hash {
	h := sha256.New()
	h.Write([]byte("STEP"))
	h.Write(stateRoot[:])
	var res types.Hash
	copy(res[:], h.Sum(nil))
	return res
}
