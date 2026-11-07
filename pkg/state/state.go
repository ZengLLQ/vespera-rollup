package state

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

// JournalEntry tracks state modifications for rollback.
type JournalEntry struct {
	addr        types.Address
	prevAccount *types.Account
	isNew       bool
}

// WorldState manages L2 account states and sparse Merkle tree commitments.
type WorldState struct {
	mu        sync.RWMutex
	accounts  map[types.Address]*types.Account
	tree      *crypto.SparseMerkleTree
	journal   []JournalEntry
	snapshots map[int]int
	snapID    int
}

func NewWorldState() *WorldState {
	return &WorldState{
		accounts:  make(map[types.Address]*types.Account),
		tree:      crypto.NewSparseMerkleTree(),
		journal:   make([]JournalEntry, 0),
		snapshots: make(map[int]int),
	}
}

// GetAccount retrieves or creates an empty account object.
func (ws *WorldState) GetAccount(addr types.Address) *types.Account {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if acc, ok := ws.accounts[addr]; ok {
		return acc.Clone()
	}
	return types.NewAccount(0, big.NewInt(0))
}

// GetBalance returns an account balance.
func (ws *WorldState) GetBalance(addr types.Address) *big.Int {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if acc, ok := ws.accounts[addr]; ok {
		return new(big.Int).Set(acc.Balance)
	}
	return big.NewInt(0)
}

// SetBalance sets an account balance, recording the prior value in the journal.
func (ws *WorldState) SetBalance(addr types.Address, bal *big.Int) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.recordChange(addr)

	acc, ok := ws.accounts[addr]
	if !ok {
		acc = types.NewAccount(0, bal)
		ws.accounts[addr] = acc
	} else {
		acc.Balance = new(big.Int).Set(bal)
	}
}

// AddBalance increments an account balance.
func (ws *WorldState) AddBalance(addr types.Address, amount *big.Int) {
	if amount.Sign() <= 0 {
		return
	}
	bal := ws.GetBalance(addr)
	ws.SetBalance(addr, new(big.Int).Add(bal, amount))
}

// SubBalance decrements an account balance with underflow prevention.
func (ws *WorldState) SubBalance(addr types.Address, amount *big.Int) error {
	if amount.Sign() <= 0 {
		return nil
	}
	bal := ws.GetBalance(addr)
	if bal.Cmp(amount) < 0 {
		return fmt.Errorf("insufficient balance: have %s, need %s", bal.String(), amount.String())
	}
	ws.SetBalance(addr, new(big.Int).Sub(bal, amount))
	return nil
}

// GetNonce returns account nonce.
func (ws *WorldState) GetNonce(addr types.Address) uint64 {
	ws.mu.RLock()
	defer ws.mu.RUnlock()
	if acc, ok := ws.accounts[addr]; ok {
		return acc.Nonce
	}
	return 0
}

// SetNonce sets account nonce.
func (ws *WorldState) SetNonce(addr types.Address, nonce uint64) {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.recordChange(addr)

	acc, ok := ws.accounts[addr]
	if !ok {
		acc = types.NewAccount(nonce, big.NewInt(0))
		ws.accounts[addr] = acc
	} else {
		acc.Nonce = nonce
	}
}

func (ws *WorldState) IncrementNonce(addr types.Address) uint64 {
	nonce := ws.GetNonce(addr)
	ws.SetNonce(addr, nonce+1)
	return nonce
}

// Snapshot creates a checkpoint index.
func (ws *WorldState) Snapshot() int {
	ws.mu.Lock()
	defer ws.mu.Unlock()
	ws.snapID++
	ws.snapshots[ws.snapID] = len(ws.journal)
	return ws.snapID
}

// RevertToSnapshot rolls back all modifications made after snapshotID.
func (ws *WorldState) RevertToSnapshot(snapID int) {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	idx, ok := ws.snapshots[snapID]
	if !ok {
		return
	}

	for i := len(ws.journal) - 1; i >= idx; i-- {
		entry := ws.journal[i]
		if entry.isNew {
			delete(ws.accounts, entry.addr)
		} else {
			ws.accounts[entry.addr] = entry.prevAccount
		}
	}

	ws.journal = ws.journal[:idx]
	delete(ws.snapshots, snapID)
}

func (ws *WorldState) recordChange(addr types.Address) {
	prev, exists := ws.accounts[addr]
	if !exists {
		ws.journal = append(ws.journal, JournalEntry{
			addr:        addr,
			prevAccount: nil,
			isNew:       true,
		})
	} else {
		ws.journal = append(ws.journal, JournalEntry{
			addr:        addr,
			prevAccount: prev.Clone(),
			isNew:       false,
		})
	}
}

// HashAccount computes the SMT leaf hash for an account.
func HashAccount(acc *types.Account) types.Hash {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, acc.Nonce)
	if acc.Balance != nil {
		h.Write(acc.Balance.Bytes())
	}
	h.Write(acc.StorageRoot[:])
	h.Write(acc.CodeHash[:])
	var res types.Hash
	copy(res[:], h.Sum(nil))
	return res
}

// Commit updates the Sparse Merkle Tree leaves and returns the new 32-byte StateRoot.
func (ws *WorldState) Commit() types.Hash {
	ws.mu.Lock()
	defer ws.mu.Unlock()

	// Update all active accounts into the tree
	for addr, acc := range ws.accounts {
		var key types.Hash
		copy(key[12:], addr[:]) // Pad 20-byte address to 32-byte key
		val := HashAccount(acc)
		ws.tree.Update(key, val)
	}

	// Clear journal after commit
	ws.journal = ws.journal[:0]
	ws.snapshots = make(map[int]int)

	return ws.tree.Root()
}

// StateRoot retrieves current state root.
func (ws *WorldState) StateRoot() types.Hash {
	return ws.tree.Root()
}
