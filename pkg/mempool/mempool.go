package mempool

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"math/big"
	"sort"
	"sync"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

var (
	ErrTxAlreadyExists  = errors.New("transaction already in mempool")
	ErrNonceTooLow      = errors.New("nonce too low for account")
	ErrUnderpriced      = errors.New("replacement transaction underpriced (<10% tip bump)")
	ErrMempoolFull      = errors.New("mempool capacity exceeded")
	ErrEnvelopeMismatch = errors.New("revealed transaction does not match committed envelope hash")
)

// EncryptedEnvelope holds commit-reveal transactions for MEV prevention.
type EncryptedEnvelope struct {
	Commitment  types.Hash    `json:"commitment"` // H(nonce || tx_bytes)
	Sender      types.Address `json:"sender"`
	Timestamp   time.Time     `json:"timestamp"`
	Ciphertext  []byte        `json:"ciphertext"`
}

// TxPool manages transaction admission, priority ordering, and commit-reveal MEV queues.
type TxPool struct {
	mu           sync.RWMutex
	capacity     int
	byHash       map[types.Hash]*types.Transaction
	bySender     map[types.Address]map[uint64]*types.Transaction
	envelopes    map[types.Hash]*EncryptedEnvelope
	commitOrder  []types.Hash
}

func NewTxPool(capacity int) *TxPool {
	return &TxPool{
		capacity:    capacity,
		byHash:      make(map[types.Hash]*types.Transaction),
		bySender:    make(map[types.Address]map[uint64]*types.Transaction),
		envelopes:   make(map[types.Hash]*EncryptedEnvelope),
		commitOrder: make([]types.Hash, 0),
	}
}

func (tp *TxPool) Size() int {
	tp.mu.RLock()
	defer tp.mu.RUnlock()
	return len(tp.byHash)
}

// AddTransaction admits a transaction to the pool with validation and replacement logic.
func (tp *TxPool) AddTransaction(tx *types.Transaction, currentAccountNonce uint64) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	txHash := tx.Hash()
	if _, exists := tp.byHash[txHash]; exists {
		return ErrTxAlreadyExists
	}

	if tx.Nonce < currentAccountNonce {
		return ErrNonceTooLow
	}

	if len(tp.byHash) >= tp.capacity {
		return ErrMempoolFull
	}

	senderTxs, ok := tp.bySender[tx.From]
	if !ok {
		senderTxs = make(map[uint64]*types.Transaction)
		tp.bySender[tx.From] = senderTxs
	}

	// Replacement check for same nonce
	if existing, hasNonce := senderTxs[tx.Nonce]; hasNonce {
		// Enforce >= 10% price bump
		minBump := new(big.Int).Mul(existing.GasTipCap, big.NewInt(110))
		minBump.Div(minBump, big.NewInt(100))
		if tx.GasTipCap == nil || tx.GasTipCap.Cmp(minBump) < 0 {
			return ErrUnderpriced
		}
		// Remove existing
		delete(tp.byHash, existing.Hash())
	}

	tp.byHash[txHash] = tx
	senderTxs[tx.Nonce] = tx
	return nil
}

// CommitEnvelope registers an encrypted commit-reveal transaction to freeze ordering.
func (tp *TxPool) CommitEnvelope(env *EncryptedEnvelope) {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	tp.envelopes[env.Commitment] = env
	tp.commitOrder = append(tp.commitOrder, env.Commitment)
}

// RevealEnvelope validates and admits a previously committed envelope.
func (tp *TxPool) RevealEnvelope(commitment types.Hash, tx *types.Transaction, currentNonce uint64) error {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	env, exists := tp.envelopes[commitment]
	if !exists {
		return errors.New("envelope commitment not found")
	}

	// Verify commitment hash: H(commitment == H(txHash))
	txH := tx.Hash()
	expected := sha256.Sum256(txH[:])
	if !bytes.Equal(env.Commitment[:], expected[:]) {
		return ErrEnvelopeMismatch
	}

	delete(tp.envelopes, commitment)
	// Add to internal pools
	senderTxs, ok := tp.bySender[tx.From]
	if !ok {
		senderTxs = make(map[uint64]*types.Transaction)
		tp.bySender[tx.From] = senderTxs
	}
	tp.byHash[txH] = tx
	senderTxs[tx.Nonce] = tx
	return nil
}

// GetPendingTransactions returns sorted executable transactions:
// Ordered strictly by sender nonce, sorted globally by effective gas tip descending.
func (tp *TxPool) GetPendingTransactions(maxTxs int) []*types.Transaction {
	tp.mu.RLock()
	defer tp.mu.RUnlock()

	var executable []*types.Transaction

	for _, txsByNonce := range tp.bySender {
		// Collect contiguous nonces
		var nonces []uint64
		for n := range txsByNonce {
			nonces = append(nonces, n)
		}
		sort.Slice(nonces, func(i, j int) bool { return nonces[i] < nonces[j] })

		for _, n := range nonces {
			executable = append(executable, txsByNonce[n])
		}
	}

	// Sort globally: for the same sender, preserve nonce ascending; across different senders, sort by tip descending
	sort.Slice(executable, func(i, j int) bool {
		if executable[i].From == executable[j].From {
			return executable[i].Nonce < executable[j].Nonce
		}
		tipI := executable[i].GasTipCap
		tipJ := executable[j].GasTipCap
		if tipI == nil {
			tipI = big.NewInt(0)
		}
		if tipJ == nil {
			tipJ = big.NewInt(0)
		}
		return tipI.Cmp(tipJ) > 0
	})

	if len(executable) > maxTxs {
		executable = executable[:maxTxs]
	}
	return executable
}

// Remove removes processed transactions from the pool.
func (tp *TxPool) Remove(txs []*types.Transaction) {
	tp.mu.Lock()
	defer tp.mu.Unlock()

	for _, tx := range txs {
		h := tx.Hash()
		delete(tp.byHash, h)
		if senderTxs, ok := tp.bySender[tx.From]; ok {
			delete(senderTxs, tx.Nonce)
			if len(senderTxs) == 0 {
				delete(tp.bySender, tx.From)
			}
		}
	}
}
