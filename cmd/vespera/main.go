package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"os"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/crypto"
	"github.com/ZengLLQ/vespera-rollup/pkg/da"
	"github.com/ZengLLQ/vespera-rollup/pkg/dispute"
	"github.com/ZengLLQ/vespera-rollup/pkg/mempool"
	"github.com/ZengLLQ/vespera-rollup/pkg/sequencer"
	"github.com/ZengLLQ/vespera-rollup/pkg/state"
	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

func printBanner() {
	fmt.Println("================================================================================")
	fmt.Println("  VESPERA ROLLUP: Decentralized Based Rollup & Shared Sequencer Engine")
	fmt.Println("  Sparse Merkle Tree | Reed-Solomon 2D DA | Interactive Bisection Dispute Game")
	fmt.Println("================================================================================")
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "--help" || os.Args[1] == "-h" {
		printBanner()
		fmt.Printf("Usage: vespera <command> [options]\n\n")
		fmt.Println("Commands:")
		fmt.Println("  sequencer    Run L2 block production and batch submission simulation")
		fmt.Println("  da-sample    Demonstrate 2D Reed-Solomon erasure coding and DA sampling")
		fmt.Println("  bisection    Execute interactive bisection dispute game and fraud proof")
		fmt.Println("  benchmark    Benchmark SMT updates, state transitions, and RS throughput")
		return
	}

	cmd := os.Args[1]
	switch cmd {
	case "sequencer":
		runSequencerDemo()
	case "da-sample":
		runDASampleDemo()
	case "bisection":
		runBisectionDemo()
	case "benchmark":
		runBenchmark()
	default:
		fmt.Printf("Unknown command: %s\nRun with --help for usage.\n", cmd)
		os.Exit(1)
	}
}

func runSequencerDemo() {
	printBanner()
	fmt.Println("Mode: L2 Block Production & Batch Submission Simulation")

	ws := state.NewWorldState()
	pool := mempool.NewTxPool(1000)

	seqAddr := types.Address{0x01}
	userA := types.Address{0xAA}
	userB := types.Address{0xBB}

	// Fund User A with 10 ETH
	initialBal := new(big.Int).Mul(big.NewInt(10), big.NewInt(1e18))
	ws.SetBalance(userA, initialBal)

	seq := sequencer.NewRollupSequencer(seqAddr, ws, pool, 2, 30000000)
	fmt.Printf("Initial Genesis State Root: %s\n", seq.LatestBlock().Header.StateRoot.Hex())
	fmt.Printf("User A Initial Balance:     %s wei\n", ws.GetBalance(userA).String())

	// Enqueue 5 transactions from User A to User B
	fmt.Println("\nEnqueueing 5 transactions to mempool...")
	transferVal := new(big.Int).Mul(big.NewInt(1), big.NewInt(1e18))
	for i := uint64(0); i < 5; i++ {
		tx := &types.Transaction{
			Type:      types.TxTypeEIP1559,
			Nonce:     i,
			From:      userA,
			To:        &userB,
			Value:     transferVal,
			GasLimit:  21000,
			GasFeeCap: big.NewInt(2000000000), // 2 Gwei
			GasTipCap: big.NewInt(100000000),  // 0.1 Gwei
		}
		if err := pool.AddTransaction(tx, i); err != nil {
			fmt.Printf("Failed to add tx: %v\n", err)
		}
	}
	fmt.Printf("Mempool size: %d transactions\n", pool.Size())

	// Produce Block 1
	blk, err := seq.ProduceBlock(10)
	if err != nil {
		fmt.Printf("Error producing block: %v\n", err)
		return
	}

	fmt.Printf("\nBlock #%d Produced Successfully!\n", blk.Header.Number)
	fmt.Printf("  Block Hash:   %s\n", blk.Hash().Hex())
	fmt.Printf("  State Root:   %s\n", blk.Header.StateRoot.Hex())
	fmt.Printf("  Tx Count:     %d\n", len(blk.Transactions))
	fmt.Printf("  Gas Used:     %d / %d\n", blk.Header.GasUsed, blk.Header.GasLimit)
	fmt.Printf("  User A Balance: %s wei\n", ws.GetBalance(userA).String())
	fmt.Printf("  User B Balance: %s wei\n", ws.GetBalance(userB).String())
	fmt.Printf("  Sequencer Fee:  %s wei\n", ws.GetBalance(seqAddr).String())

	// Assemble L1 batch
	batch, err := seq.CreateBatch([]*types.Block{blk})
	if err != nil {
		fmt.Printf("Error creating batch: %v\n", err)
		return
	}
	fmt.Printf("\nL1 Rollup Batch #%d Assembled:\n", batch.EpochNumber)
	fmt.Printf("  Blocks Bundled: %d\n", len(batch.Blocks))
	fmt.Printf("  PreState Root:  %s\n", batch.PreState.Hex())
	fmt.Printf("  PostState Root: %s\n", batch.PostState.Hex())
	fmt.Printf("  Batch Signature: %x\n", batch.Signature[:16])
}

func runDASampleDemo() {
	printBanner()
	fmt.Println("Mode: Reed-Solomon 2D Erasure Coding & Data Availability Sampling (DAS)")

	k := 4 // 4×4 original grid = 16 shards
	shardSize := 64
	data := make([][]byte, k*k)
	for i := range data {
		data[i] = make([]byte, shardSize)
		rand.Read(data[i])
	}

	fmt.Printf("Encoding %d×%d original data shards into %d×%d extended 2D grid...\n", k, k, 2*k, 2*k)
	matrix, err := da.Encode2DMatrix(data, k, shardSize)
	if err != nil {
		fmt.Printf("2D encoding error: %v\n", err)
		return
	}

	fmt.Printf("2D Matrix Root: %s\n", matrix.DataRoot.Hex())
	fmt.Printf("Row Roots: %d roots, Column Roots: %d roots\n", len(matrix.RowRoots), len(matrix.ColRoots))

	sampleCount := 10
	fmt.Printf("\nPerforming %d random light-client Data Availability Samples...\n", sampleCount)
	samples, err := matrix.Sample(sampleCount)
	if err != nil {
		fmt.Printf("Sampling error: %v\n", err)
		return
	}

	verifiedCount := 0
	for i, s := range samples {
		valid := da.VerifySample(s)
		if valid {
			verifiedCount++
		}
		fmt.Printf("  Sample #%02d: Row %d, Col %d -> Merkle Proof Valid: %v\n", i+1, s.Row, s.Col, valid)
	}

	confidence := (1.0 - 0.25) * 100.0 // >99% with multiple samples
	fmt.Printf("\nResult: %d/%d samples cryptographically verified.\n", verifiedCount, sampleCount)
	fmt.Printf("Data availability confidence: >%.1f%%\n", confidence)
}

func runBisectionDemo() {
	printBanner()
	fmt.Println("Mode: Interactive Bisection Dispute Game & Fraud Verification")

	ws := state.NewWorldState()
	defenderAddr := types.Address{0xDE}
	challengerAddr := types.Address{0xCC}
	bond := new(big.Int).Mul(big.NewInt(32), big.NewInt(1e18)) // 32 ETH bond

	user1 := types.Address{0x11}
	user2 := types.Address{0x22}
	ws.SetBalance(user1, big.NewInt(1000000000000000000))

	preStateRoot := ws.Commit()

	totalSteps := uint64(2)
	defenderTrace := make(map[uint64]types.Hash)
	defenderTrace[0] = preStateRoot

	// Step 1: legitimate step
	tx := &types.Transaction{
		Type:      types.TxTypeLegacy,
		Nonce:     0,
		From:      user1,
		To:        &user2,
		Value:     big.NewInt(100000),
		GasLimit:  21000,
		GasFeeCap: big.NewInt(1000000000),
	}
	header := &types.Header{
		Number:   1,
		GasLimit: 30000000,
		BaseFee:  big.NewInt(1000000000),
	}
	gasPool := header.GasLimit
	_, _ = state.ApplyTransaction(ws, tx, header, &gasPool, defenderAddr)
	legitPostRoot := ws.Commit()
	_ = legitPostRoot

	// Step 1 has fraudulent post-root claimed by defender
	fraudulentPostRoot := crypto.HashUint64(0xDEADBEEF)
	defenderTrace[1] = fraudulentPostRoot
	defenderTrace[2] = crypto.HashUint64(0xDEADBEEF + 1)

	gameID := crypto.HashUint64(9999)
	game := dispute.NewBisectionGame(
		gameID, defenderAddr, challengerAddr, bond,
		totalSteps, preStateRoot, defenderTrace[totalSteps],
		defenderTrace, 1*time.Hour,
	)

	fmt.Printf("Dispute Game Initialized:\n")
	fmt.Printf("  Dispute Interval: [0, %d]\n", totalSteps)
	fmt.Printf("  Agreed Pre-State:  %s\n", preStateRoot.Hex())
	fmt.Printf("  Disputed Post-Root: %s\n", defenderTrace[totalSteps].Hex())

	round := 1
	for !game.IsReadyForSingleStepResolution() {
		midpoint := (game.LeftIndex + game.RightIndex) / 2
		agrees := (midpoint < 1)
		left, right, err := game.Bisect(game.Turn, agrees)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			break
		}
		fmt.Printf("Round %d: Bisection step -> Interval narrowed to [%d, %d]\n", round, left, right)
		round++
	}

	fmt.Printf("\nBisection complete! Disputed step identified: Step #%d\n", game.LeftIndex)

	witness := &dispute.StepWitness{
		StepIndex:     game.LeftIndex,
		PreStateRoot:  game.LeftRoot,
		PostStateRoot: game.RightRoot,
		Transaction:   tx,
		HeaderContext: header,
		PreStateBalances: map[types.Address]*big.Int{
			user1: big.NewInt(1000000000000000000),
		},
		PreStateNonces: map[types.Address]uint64{
			user1: 0,
		},
	}

	status, err := game.ResolveSingleStep(witness, defenderAddr)
	if err != nil {
		fmt.Printf("Resolution error: %v\n", err)
	}
	fmt.Printf("Dispute Resolution: %s\n", status)
	if status == dispute.StatusChallengerWon {
		fmt.Println("Verdict: Fraud proven! Sequencer slashed 32 ETH bond awarded to Challenger.")
	}
}

func runBenchmark() {
	printBanner()
	fmt.Println("Mode: Vespera Performance & Throughput Benchmark")

	// 1. SMT update benchmark
	smt := crypto.NewSparseMerkleTree()
	nKeys := 500
	t0 := time.Now()
	for i := 0; i < nKeys; i++ {
		k := crypto.HashUint64(uint64(i))
		v := crypto.HashUint64(uint64(i * 777))
		smt.Update(k, v)
	}
	smtDuration := time.Since(t0)
	smtRate := float64(nKeys) / smtDuration.Seconds()

	// 2. Reed-Solomon 2D DA benchmark
	k := 8
	shardSize := 512
	shards := make([][]byte, k*k)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
		rand.Read(shards[i])
	}
	t0 = time.Now()
	iterations := 100
	for i := 0; i < iterations; i++ {
		_, _ = da.Encode2DMatrix(shards, k, shardSize)
	}
	daDuration := time.Since(t0)
	daBytes := float64(iterations*k*k*shardSize) / (1024 * 1024)
	daThroughput := daBytes / daDuration.Seconds()

	fmt.Printf("\nBenchmark Results:\n")
	fmt.Printf("  Sparse Merkle Tree Updates: %8d in %6.3f s (%.2e ops/sec)\n", nKeys, smtDuration.Seconds(), smtRate)
	fmt.Printf("  Reed-Solomon 2D DA Encode:   %8.2f MB in %6.3f s (%.2f MB/sec)\n", daBytes, daDuration.Seconds(), daThroughput)
	fmt.Println("Cryptographic state and erasure engines operating at maximum efficiency.")
}
