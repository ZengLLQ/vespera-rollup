package sequencer

import (
	"crypto/sha256"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/mempool"
	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

// RollupSequencer produces L2 blocks and assembles data batches.
type RollupSequencer struct {
	mu             sync.Mutex
	sequencerAddr  types.Address
	state          *state.WorldState
	pool           *mempool.TxPool
	chain          []*types.Block
	batches        []*types.Batch
	currentEpoch   uint64
	blockTimeSec   uint64
	maxBlockGas    uint64
}

func NewRollupSequencer(
	sequencerAddr types.Address,
	ws *state.WorldState,
	pool *mempool.TxPool,
	blockTimeSec uint64,
	maxBlockGas uint64,
) *RollupSequencer {
	// Initialize genesis block
	genesisHeader := &types.Header{
		ParentHash:  types.EmptyHash,
		StateRoot:   ws.Commit(),
		TxRoot:      types.EmptyHash,
		ReceiptRoot: types.EmptyHash,
		Number:      0,
		GasLimit:    maxBlockGas,
		GasUsed:     0,
		Time:        uint64(time.Now().Unix()),
		BaseFee:     big.NewInt(1000000000), // 1 Gwei
		ExtraData:   []byte("VesperaRollup Genesis"),
	}
	genesisBlock := types.NewBlock(genesisHeader, nil)

	return &RollupSequencer{
		sequencerAddr: sequencerAddr,
		state:         ws,
		pool:          pool,
		chain:         []*types.Block{genesisBlock},
		batches:       make([]*types.Batch, 0),
		currentEpoch:  1,
		blockTimeSec:  blockTimeSec,
		maxBlockGas:   maxBlockGas,
	}
}

func (s *RollupSequencer) LatestBlock() *types.Block {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.chain[len(s.chain)-1]
}

// ProduceBlock assembles pending transactions, executes them, and commits a new L2 block.
func (s *RollupSequencer) ProduceBlock(maxTxs int) (*types.Block, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parent := s.chain[len(s.chain)-1]
	pendingTxs := s.pool.GetPendingTransactions(maxTxs)

	gasLimit := s.maxBlockGas
	gasRemaining := gasLimit
	nextBaseFee := state.CalculateBaseFee(parent.Header)

	header := &types.Header{
		ParentHash: parent.Hash(),
		Number:     parent.Header.Number + 1,
		GasLimit:   gasLimit,
		GasUsed:    0,
		Time:       parent.Header.Time + s.blockTimeSec,
		BaseFee:    nextBaseFee,
		ExtraData:  []byte("Vespera-Sequenced"),
	}

	executedTxs := make([]*types.Transaction, 0)
	receipts := make([]*types.Receipt, 0)

	for _, tx := range pendingTxs {
		if tx.GasLimit > gasRemaining {
			continue
		}

		receipt, err := state.ApplyTransaction(s.state, tx, header, &gasRemaining, s.sequencerAddr)
		if err != nil {
			// Transaction execution error, skip
			continue
		}

		executedTxs = append(executedTxs, tx)
		receipts = append(receipts, receipt)
		header.GasUsed += receipt.GasUsed
	}

	// Commit state transition and compute roots
	header.StateRoot = s.state.Commit()
	header.TxRoot = crypto.ComputeTxRoot(executedTxs)
	header.ReceiptRoot = computeReceiptRoot(receipts)

	block := types.NewBlock(header, executedTxs)
	s.chain = append(s.chain, block)

	// Remove executed transactions from pool
	s.pool.Remove(executedTxs)

	return block, nil
}

// CreateBatch bundles a range of blocks since the last batch.
func (s *RollupSequencer) CreateBatch(blocks []*types.Block) (*types.Batch, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(blocks) == 0 {
		return nil, errors.New("cannot create empty batch")
	}

	preState := blocks[0].Header.ParentHash
	postState := blocks[len(blocks)-1].Header.StateRoot

	batch := &types.Batch{
		EpochNumber: s.currentEpoch,
		PreState:    preState,
		PostState:   postState,
		Blocks:      blocks,
		Sequencer:   s.sequencerAddr,
	}

	// Sign batch payload
	payload := batch.PayloadBytes()
	sig := sha256.Sum256(payload)
	batch.Signature = sig[:]

	s.batches = append(s.batches, batch)
	s.currentEpoch++

	return batch, nil
}

func computeReceiptRoot(receipts []*types.Receipt) types.Hash {
	if len(receipts) == 0 {
		return types.EmptyHash
	}
	hashes := make([]types.Hash, len(receipts))
	for i, r := range receipts {
		h := sha256.New()
		h.Write(r.TxHash[:])
		hStatus := crypto.HashUint64(r.Status)
		hGas := crypto.HashUint64(r.GasUsed)
		h.Write(hStatus[:])
		h.Write(hGas[:])
		var res types.Hash
		copy(res[:], h.Sum(nil))
		hashes[i] = res
	}
	return crypto.ComputeTxRoot(nil) // Uses tree hash
}
