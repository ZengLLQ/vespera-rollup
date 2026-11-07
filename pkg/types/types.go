package types

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
)

// Address represents a 20-byte account address.
type Address [20]byte

// Hash represents a 32-byte cryptographic hash.
type Hash [32]byte

var (
	EmptyHash    = Hash{}
	EmptyAddress = Address{}
)

func HexToAddress(s string) (Address, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Address{}, err
	}
	if len(b) > 20 {
		return Address{}, fmt.Errorf("hex string exceeds 20 bytes")
	}
	var a Address
	copy(a[20-len(b):], b)
	return a, nil
}

func HexToHash(s string) (Hash, error) {
	if len(s) >= 2 && s[:2] == "0x" {
		s = s[2:]
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return Hash{}, err
	}
	if len(b) > 32 {
		return Hash{}, fmt.Errorf("hex string exceeds 32 bytes")
	}
	var h Hash
	copy(h[32-len(b):], b)
	return h, nil
}

func (a Address) Hex() string {
	return "0x" + hex.EncodeToString(a[:])
}

func (h Hash) Hex() string {
	return "0x" + hex.EncodeToString(h[:])
}

func (h Hash) IsZero() bool {
	return h == EmptyHash
}

// TxType defines transaction formats.
type TxType uint8

const (
	TxTypeLegacy  TxType = 0x00
	TxTypeEIP1559 TxType = 0x02
	TxTypeDeposit TxType = 0x7E // L1 -> L2 force inclusion deposit
)

// Account represents an account state in the L2 world state.
type Account struct {
	Nonce       uint64   `json:"nonce"`
	Balance     *big.Int `json:"balance"`
	StorageRoot Hash     `json:"storage_root"`
	CodeHash    Hash     `json:"code_hash"`
}

func NewAccount(nonce uint64, balance *big.Int) *Account {
	if balance == nil {
		balance = new(big.Int)
	}
	return &Account{
		Nonce:       nonce,
		Balance:     new(big.Int).Set(balance),
		StorageRoot: EmptyHash,
		CodeHash:    EmptyHash,
	}
}

func (acc *Account) Clone() *Account {
	return &Account{
		Nonce:       acc.Nonce,
		Balance:     new(big.Int).Set(acc.Balance),
		StorageRoot: acc.StorageRoot,
		CodeHash:    acc.CodeHash,
	}
}

// Transaction represents an L2 atomic state transition request.
type Transaction struct {
	Type      TxType   `json:"type"`
	Nonce     uint64   `json:"nonce"`
	From      Address  `json:"from"`
	To        *Address `json:"to"` // nil indicates contract creation
	Value     *big.Int `json:"value"`
	Data      []byte   `json:"data"`
	GasLimit  uint64   `json:"gas_limit"`
	GasFeeCap *big.Int `json:"gas_fee_cap"` // Max fee per gas
	GasTipCap *big.Int `json:"gas_tip_cap"` // Priority fee per gas
	Signature []byte   `json:"signature"`
}

func (tx *Transaction) Hash() Hash {
	h := sha256.New()
	h.Write([]byte{byte(tx.Type)})
	binary.Write(h, binary.BigEndian, tx.Nonce)
	h.Write(tx.From[:])
	if tx.To != nil {
		h.Write(tx.To[:])
	} else {
		h.Write(make([]byte, 20))
	}
	if tx.Value != nil {
		h.Write(tx.Value.Bytes())
	}
	binary.Write(h, binary.BigEndian, tx.GasLimit)
	if tx.GasFeeCap != nil {
		h.Write(tx.GasFeeCap.Bytes())
	}
	if tx.GasTipCap != nil {
		h.Write(tx.GasTipCap.Bytes())
	}
	h.Write(tx.Data)
	var res Hash
	copy(res[:], h.Sum(nil))
	return res
}

// Header represents block metadata.
type Header struct {
	ParentHash  Hash     `json:"parent_hash"`
	StateRoot   Hash     `json:"state_root"`
	TxRoot      Hash     `json:"tx_root"`
	ReceiptRoot Hash     `json:"receipt_root"`
	Number      uint64   `json:"number"`
	GasLimit    uint64   `json:"gas_limit"`
	GasUsed     uint64   `json:"gas_used"`
	Time        uint64   `json:"time"`
	BaseFee     *big.Int `json:"base_fee"`
	ExtraData   []byte   `json:"extra_data"`
}

func (hdr *Header) Hash() Hash {
	h := sha256.New()
	h.Write(hdr.ParentHash[:])
	h.Write(hdr.StateRoot[:])
	h.Write(hdr.TxRoot[:])
	h.Write(hdr.ReceiptRoot[:])
	binary.Write(h, binary.BigEndian, hdr.Number)
	binary.Write(h, binary.BigEndian, hdr.GasLimit)
	binary.Write(h, binary.BigEndian, hdr.GasUsed)
	binary.Write(h, binary.BigEndian, hdr.Time)
	if hdr.BaseFee != nil {
		h.Write(hdr.BaseFee.Bytes())
	}
	h.Write(hdr.ExtraData)
	var res Hash
	copy(res[:], h.Sum(nil))
	return res
}

// Block wraps header and transactions.
type Block struct {
	Header       *Header        `json:"header"`
	Transactions []*Transaction `json:"transactions"`
}

func NewBlock(header *Header, txs []*Transaction) *Block {
	return &Block{
		Header:       header,
		Transactions: txs,
	}
}

func (b *Block) Hash() Hash {
	return b.Header.Hash()
}

// Receipt stores transaction execution results.
type Receipt struct {
	TxHash            Hash     `json:"tx_hash"`
	Status            uint64   `json:"status"` // 1 = success, 0 = failure
	GasUsed           uint64   `json:"gas_used"`
	CumulativeGasUsed uint64   `json:"cumulative_gas_used"`
	LogsBloom         [256]byte `json:"logs_bloom"`
}

// Batch represents a bundle of L2 blocks submitted by the sequencer to L1.
type Batch struct {
	EpochNumber uint64   `json:"epoch_number"`
	PreState    Hash     `json:"pre_state"`
	PostState   Hash     `json:"post_state"`
	Blocks      []*Block `json:"blocks"`
	Sequencer   Address  `json:"sequencer"`
	Signature   []byte   `json:"signature"`
}

func (b *Batch) PayloadBytes() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, b.EpochNumber)
	buf.Write(b.PreState[:])
	buf.Write(b.PostState[:])
	binary.Write(buf, binary.BigEndian, uint32(len(b.Blocks)))
	for _, blk := range b.Blocks {
		h := blk.Hash()
		buf.Write(h[:])
	}
	return buf.Bytes()
}
