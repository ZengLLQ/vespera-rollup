package state

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

const (
	TxGasBase            uint64 = 21000
	TxDataZeroGas        uint64 = 4
	TxDataNonZeroGas     uint64 = 16
	DefaultTargetGasUsed uint64 = 15000000
	ElasticityMultiplier uint64 = 2
	BaseFeeMaxChangeDenominator uint64 = 8
)

var (
	ErrInsufficientBalance = errors.New("insufficient balance for gas and transfer")
	ErrGasLimitExceeded    = errors.New("transaction gas limit exceeds block gas remaining")
	ErrFeeCapTooLow        = errors.New("max fee per gas less than block base fee")
	ErrNonceMismatch       = errors.New("transaction nonce mismatch")
	ErrIntrinsicGas        = errors.New("intrinsic gas exceeds gas limit")
)

// IntrinsicGas computes the minimum gas required for transaction execution.
func IntrinsicGas(data []byte) uint64 {
	gas := TxGasBase
	for _, b := range data {
		if b == 0 {
			gas += TxDataZeroGas
		} else {
			gas += TxDataNonZeroGas
		}
	}
	return gas
}

// CalculateBaseFee computes EIP-1559 next block base fee.
func CalculateBaseFee(parent *types.Header) *big.Int {
	if parent == nil || parent.BaseFee == nil || parent.BaseFee.Sign() == 0 {
		return big.NewInt(1000000000) // 1 Gwei initial base fee
	}

	targetGas := parent.GasLimit / ElasticityMultiplier
	if targetGas == 0 {
		targetGas = DefaultTargetGasUsed
	}

	baseFee := new(big.Int).Set(parent.BaseFee)
	if parent.GasUsed == targetGas {
		return baseFee
	}

	if parent.GasUsed > targetGas {
		gasDelta := parent.GasUsed - targetGas
		numerator := new(big.Int).Mul(baseFee, new(big.Int).SetUint64(gasDelta))
		denominator := new(big.Int).SetUint64(targetGas * BaseFeeMaxChangeDenominator)
		feeDelta := new(big.Int).Div(numerator, denominator)
		if feeDelta.Sign() == 0 {
			feeDelta = big.NewInt(1)
		}
		return new(big.Int).Add(baseFee, feeDelta)
	}

	// parent.GasUsed < targetGas
	gasDelta := targetGas - parent.GasUsed
	numerator := new(big.Int).Mul(baseFee, new(big.Int).SetUint64(gasDelta))
	denominator := new(big.Int).SetUint64(targetGas * BaseFeeMaxChangeDenominator)
	feeDelta := new(big.Int).Div(numerator, denominator)
	nextFee := new(big.Int).Sub(baseFee, feeDelta)
	if nextFee.Sign() <= 0 {
		return big.NewInt(1)
	}
	return nextFee
}

// ApplyTransaction executes a single transaction against the world state.
func ApplyTransaction(
	ws *WorldState,
	tx *types.Transaction,
	header *types.Header,
	gasPool *uint64,
	sequencerAddr types.Address,
) (*types.Receipt, error) {
	// 1. Gas pool availability
	if tx.GasLimit > *gasPool {
		return nil, ErrGasLimitExceeded
	}

	// 2. Intrinsic gas check
	intrinsic := IntrinsicGas(tx.Data)
	if tx.GasLimit < intrinsic {
		return nil, ErrIntrinsicGas
	}

	// 3. EIP-1559 base fee check (Deposits bypass fee check)
	baseFee := header.BaseFee
	if baseFee == nil {
		baseFee = big.NewInt(0)
	}

	if tx.Type != types.TxTypeDeposit {
		if tx.GasFeeCap != nil && tx.GasFeeCap.Cmp(baseFee) < 0 {
			return nil, ErrFeeCapTooLow
		}
	}

	// 4. Nonce validation
	currentNonce := ws.GetNonce(tx.From)
	if tx.Type != types.TxTypeDeposit && tx.Nonce != currentNonce {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrNonceMismatch, currentNonce, tx.Nonce)
	}

	// 5. Calculate upfront payment
	maxFeePerGas := baseFee
	if tx.GasFeeCap != nil {
		maxFeePerGas = tx.GasFeeCap
	}
	maxGasCost := new(big.Int).Mul(new(big.Int).SetUint64(tx.GasLimit), maxFeePerGas)
	totalUpfront := new(big.Int).Add(maxGasCost, tx.Value)

	if tx.Type != types.TxTypeDeposit {
		senderBal := ws.GetBalance(tx.From)
		if senderBal.Cmp(totalUpfront) < 0 {
			return nil, ErrInsufficientBalance
		}
		// Deduct upfront cost
		ws.SubBalance(tx.From, totalUpfront)
		// Increment nonce
		ws.IncrementNonce(tx.From)
	}

	// 6. Execute state transfer inside snapshot boundary
	snap := ws.Snapshot()
	var gasUsed uint64 = intrinsic
	status := uint64(1)

	if tx.To != nil {
		// Value transfer
		if tx.Value != nil && tx.Value.Sign() > 0 {
			ws.AddBalance(*tx.To, tx.Value)
		}
	} else {
		// Contract creation mock deployment
		if tx.Value != nil && tx.Value.Sign() > 0 {
			// Mock contract address
			ws.AddBalance(types.Address{}, tx.Value)
		}
	}

	// 7. Settlement and fee distribution
	if tx.Type != types.TxTypeDeposit {
		// Priority tip calculation: effectiveTip = min(tipCap, feeCap - baseFee)
		feeCap := tx.GasFeeCap
		if feeCap == nil {
			feeCap = baseFee
		}
		effectiveGasPrice := new(big.Int).Set(baseFee)
		if tx.GasTipCap != nil {
			tipRoom := new(big.Int).Sub(feeCap, baseFee)
			tip := tx.GasTipCap
			if tip.Cmp(tipRoom) > 0 {
				tip = tipRoom
			}
			effectiveGasPrice.Add(effectiveGasPrice, tip)
			// Tip goes to sequencer
			sequencerReward := new(big.Int).Mul(new(big.Int).SetUint64(gasUsed), tip)
			ws.AddBalance(sequencerAddr, sequencerReward)
		}

		// Refund unused gas: (gasLimit - gasUsed) * feeCap
		unusedGas := tx.GasLimit - gasUsed
		gasRefund := new(big.Int).Mul(new(big.Int).SetUint64(unusedGas), feeCap)
		ws.AddBalance(tx.From, gasRefund)
	}

	_ = snap
	*gasPool -= gasUsed

	receipt := &types.Receipt{
		TxHash:            tx.Hash(),
		Status:            status,
		GasUsed:           gasUsed,
		CumulativeGasUsed: header.GasUsed + gasUsed,
	}

	return receipt, nil
}
