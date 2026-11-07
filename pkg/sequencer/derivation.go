package sequencer

import (
	"errors"
	"math/big"
	"sync"

	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

// L1DepositEvent represents an L1->L2 bridging transaction force-included into L2.
type L1DepositEvent struct {
	DepositID   uint64        `json:"deposit_id"`
	BlockNumber uint64        `json:"block_number"`
	From        types.Address `json:"from"`
	To          types.Address `json:"to"`
	Value       *big.Int      `json:"value"`
	GasLimit    uint64        `json:"gas_limit"`
	Data        []byte        `json:"data"`
}

// DerivationPipeline maintains canonical L2 chain derived from L1 data and deposits.
type DerivationPipeline struct {
	mu                sync.RWMutex
	depositQueue      []*L1DepositEvent
	nextDepositID     uint64
	maxDepositDelay   uint64
	canonicalL2Chain  []*types.Block
	l1BlockOrigin     uint64
	derivedState      *state.WorldState
}

func NewDerivationPipeline(genesis *types.Block, ws *state.WorldState, maxDepositDelay uint64) *DerivationPipeline {
	return &DerivationPipeline{
		depositQueue:     make([]*L1DepositEvent, 0),
		nextDepositID:    1,
		maxDepositDelay:  maxDepositDelay,
		canonicalL2Chain: []*types.Block{genesis},
		l1BlockOrigin:    1,
		derivedState:     ws,
	}
}

// EnqueueL1Deposit queues an L1 deposit that must be processed in the derivation window.
func (dp *DerivationPipeline) EnqueueL1Deposit(from, to types.Address, value *big.Int, gasLimit uint64, data []byte) *L1DepositEvent {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	dep := &L1DepositEvent{
		DepositID:   dp.nextDepositID,
		BlockNumber: dp.l1BlockOrigin,
		From:        from,
		To:          to,
		Value:       new(big.Int).Set(value),
		GasLimit:    gasLimit,
		Data:        append([]byte(nil), data...),
	}
	dp.depositQueue = append(dp.depositQueue, dep)
	dp.nextDepositID++
	return dep
}

// DeriveFromBatch validates and applies an L1 posted batch into the canonical L2 chain.
func (dp *DerivationPipeline) DeriveFromBatch(batch *types.Batch, sequencerAddr types.Address) error {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if len(batch.Blocks) == 0 {
		return errors.New("empty batch")
	}

	for _, blk := range batch.Blocks {
		lastCanonical := dp.canonicalL2Chain[len(dp.canonicalL2Chain)-1]
		if blk.Header.ParentHash != lastCanonical.Hash() {
			return errors.New("batch block parent hash mismatch: reorg detected")
		}

		// Execute any pending force-included deposits that have reached their delay deadline
		gasRemaining := blk.Header.GasLimit
		for len(dp.depositQueue) > 0 {
			dep := dp.depositQueue[0]
			depositTx := &types.Transaction{
				Type:     types.TxTypeDeposit,
				Nonce:    dep.DepositID,
				From:     dep.From,
				To:       &dep.To,
				Value:    dep.Value,
				GasLimit: dep.GasLimit,
				Data:     dep.Data,
			}
			dp.derivedState.AddBalance(dep.To, dep.Value)
			_, err := state.ApplyTransaction(dp.derivedState, depositTx, blk.Header, &gasRemaining, sequencerAddr)
			if err == nil {
				// Successfully forced
				dp.depositQueue = dp.depositQueue[1:]
			} else {
				break
			}
		}

		// Advance canonical chain
		dp.canonicalL2Chain = append(dp.canonicalL2Chain, blk)
	}

	return nil
}

// HandleL1Reorg invalidates L2 blocks derived from reorged L1 history.
func (dp *DerivationPipeline) HandleL1Reorg(reorgDepth int) error {
	dp.mu.Lock()
	defer dp.mu.Unlock()

	if reorgDepth >= len(dp.canonicalL2Chain) {
		return errors.New("reorg depth exceeds canonical chain length")
	}

	// Truncate canonical chain
	newHead := len(dp.canonicalL2Chain) - reorgDepth
	dp.canonicalL2Chain = dp.canonicalL2Chain[:newHead]
	return nil
}

func (dp *DerivationPipeline) CanonicalHead() *types.Block {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	return dp.canonicalL2Chain[len(dp.canonicalL2Chain)-1]
}

func (dp *DerivationPipeline) PendingDepositCount() int {
	dp.mu.RLock()
	defer dp.mu.RUnlock()
	return len(dp.depositQueue)
}
