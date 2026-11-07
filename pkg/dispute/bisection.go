package dispute

import (
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"github.com/ZengLLQ/vespera-rollup/pkg/types"
)

type GameStatus string

const (
	StatusInProgress    GameStatus = "IN_PROGRESS"
	StatusChallengerWon GameStatus = "CHALLENGER_WON"
	StatusDefenderWon   GameStatus = "DEFENDER_WON"
)

// BisectionGame models an interactive O(log N) verification game between Defender and Challenger.
type BisectionGame struct {
	mu             sync.Mutex
	GameID         types.Hash
	Defender       types.Address
	Challenger     types.Address
	BondAmount     *big.Int
	LeftIndex      uint64
	RightIndex     uint64
	LeftRoot       types.Hash
	RightRoot      types.Hash
	DefenderTrace  map[uint64]types.Hash // Step index -> State root
	Turn           types.Address
	Status         GameStatus
	Timeout        time.Duration
	LastMoveTime   time.Time
	Verifier       *SingleStepVerifier
}

func NewBisectionGame(
	gameID types.Hash,
	defender, challenger types.Address,
	bondAmount *big.Int,
	totalSteps uint64,
	agreedPreState types.Hash,
	disputedPostState types.Hash,
	defenderTrace map[uint64]types.Hash,
	timeout time.Duration,
) *BisectionGame {
	return &BisectionGame{
		GameID:        gameID,
		Defender:      defender,
		Challenger:    challenger,
		BondAmount:    new(big.Int).Set(bondAmount),
		LeftIndex:     0,
		RightIndex:    totalSteps,
		LeftRoot:      agreedPreState,
		RightRoot:     disputedPostState,
		DefenderTrace: defenderTrace,
		Turn:          challenger, // Challenger initiates bisection
		Status:        StatusInProgress,
		Timeout:       timeout,
		LastMoveTime:  time.Now(),
		Verifier:      NewSingleStepVerifier(),
	}
}

// Bisect processes an interactive query-response step halving the search space.
// If agreesWithMidpoint == true, the disagreement lies in [Midpoint, Right].
// If agreesWithMidpoint == false, the disagreement lies in [Left, Midpoint].
func (g *BisectionGame) Bisect(player types.Address, agreesWithMidpoint bool) (uint64, uint64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.Status != StatusInProgress {
		return 0, 0, fmt.Errorf("game already concluded with status %s", g.Status)
	}

	if player != g.Turn {
		return 0, 0, errors.New("not player's turn")
	}

	midpoint := (g.LeftIndex + g.RightIndex) / 2
	midRoot, hasMid := g.DefenderTrace[midpoint]
	if !hasMid {
		// Defender missing required state trace, forfeits
		g.Status = StatusChallengerWon
		return 0, 0, errors.New("defender trace missing at midpoint, challenger wins")
	}

	if agreesWithMidpoint {
		g.LeftIndex = midpoint
		g.LeftRoot = midRoot
	} else {
		g.RightIndex = midpoint
		g.RightRoot = midRoot
	}

	// Switch turn
	if g.Turn == g.Challenger {
		g.Turn = g.Defender
	} else {
		g.Turn = g.Challenger
	}
	g.LastMoveTime = time.Now()

	return g.LeftIndex, g.RightIndex, nil
}

// IsReadyForSingleStepResolution returns true when search is narrowed down to a single step (Right - Left == 1).
func (g *BisectionGame) IsReadyForSingleStepResolution() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.RightIndex-g.LeftIndex == 1
}

// ResolveSingleStep resolves the dispute by deterministically verifying the single contested step.
func (g *BisectionGame) ResolveSingleStep(witness *StepWitness, sequencerAddr types.Address) (GameStatus, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.Status != StatusInProgress {
		return g.Status, errors.New("game already finalized")
	}

	if g.RightIndex-g.LeftIndex != 1 {
		return g.Status, fmt.Errorf("search interval not narrowed to single step: [%d, %d]", g.LeftIndex, g.RightIndex)
	}

	// Ensure witness matches agreed pre-state and disputed post-state
	if witness.PreStateRoot != g.LeftRoot {
		return g.Status, errors.New("witness pre-state root mismatch with agreed boundary")
	}
	if witness.PostStateRoot != g.RightRoot {
		return g.Status, errors.New("witness post-state root mismatch with disputed boundary")
	}

	isValid, actualPostRoot, err := g.Verifier.VerifyStep(witness, sequencerAddr)
	if err != nil {
		return g.Status, fmt.Errorf("step verification execution error: %w", err)
	}

	if isValid {
		// Defender was truthful, challenger made a false accusation
		g.Status = StatusDefenderWon
	} else {
		// Contested state root was fraudulent, challenger caught the sequencer!
		_ = actualPostRoot
		g.Status = StatusChallengerWon
	}

	return g.Status, nil
}
