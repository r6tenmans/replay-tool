// r6-replay-tool — comprehensive Rainbow Six Siege .rec replay analyzer.
//
// Combines position tracking, bone/aim data, ammo/weapon analysis, equipment
// loadouts, shot reconstruction, health monitoring, entity classification,
// camera frames, timer ticks, and game event extraction into a single tool.
//
// Usage:
//
//	r6-replay-tool <file.rec>              # analyze and print JSON to stdout
//	r6-replay-tool -o output.json file.rec # write to file
//	r6-replay-tool -pretty file.rec        # pretty-printed JSON
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/wnc-replay/replay-tool/analysis"
	"github.com/wnc-replay/replay-tool/dissect"
)

func main() {
	outFile := flag.String("o", "", "Output JSON file (default: stdout)")
	pretty := flag.Bool("pretty", false, "Pretty-print JSON output")
	headerOnly := flag.Bool("header", false, "Only parse header info (fast)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: r6-replay-tool [flags] <file.rec>")
		fmt.Fprintln(os.Stderr, "\nFlags:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	recPath := flag.Arg(0)

	// Open .rec file
	f, err := os.Open(recPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error opening file: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	// Create dissect reader (decompresses the replay)
	reader, err := dissect.NewReader(f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading replay: %v\n", err)
		os.Exit(1)
	}

	// Capture decompressed bytes BEFORE Read() clears the buffer
	var rawBuf bytes.Buffer
	reader.Write(&rawBuf)
	rawData := rawBuf.Bytes()

	// Read() processes patterns: players, feedback, scores, time, ammo
	err = reader.Read()
	if err != nil && !dissect.Ok(err) {
		fmt.Fprintf(os.Stderr, "Warning: partial read: %v\n", err)
	}

	// Build output
	output := buildOutput(reader, rawData, *headerOnly)

	// Marshal JSON
	var jsonBytes []byte
	if *pretty {
		jsonBytes, err = json.MarshalIndent(output, "", "  ")
	} else {
		jsonBytes, err = json.Marshal(output)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}

	// Write output
	if *outFile != "" {
		if err := os.WriteFile(*outFile, jsonBytes, 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing file: %v\n", err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Wrote %d bytes to %s\n", len(jsonBytes), *outFile)
	} else {
		os.Stdout.Write(jsonBytes)
		fmt.Println()
	}
}

// FullOutput combines header data with binary analysis.
type FullOutput struct {
	Header   HeaderInfo              `json:"header"`
	Analysis *analysis.RoundAnalysis `json:"analysis,omitempty"`
}

// HeaderInfo is the round header from the dissect library.
type HeaderInfo struct {
	GameVersion   string             `json:"gameVersion"`
	MatchID       string             `json:"matchId"`
	MapName       string             `json:"mapName"`
	GameMode      string             `json:"gameMode"`
	RoundNumber   int                `json:"roundNumber"`
	Teams         []TeamInfo         `json:"teams"`
	Players       []PlayerInfoHeader `json:"players"`
	MatchFeedback []FeedbackInfo     `json:"matchFeedback,omitempty"`
}

type TeamInfo struct {
	Name  string `json:"name"`
	Score int    `json:"score"`
	Won   bool   `json:"won"`
	Role  string `json:"role"`
}

type PlayerInfoHeader struct {
	Username        string `json:"username"`
	Operator        string `json:"operator"`
	InitialOperator string `json:"initialOperator,omitempty"`
	TeamIndex       int    `json:"teamIndex"`
	IsAttack        bool   `json:"isAttack"`
	Spawn           string `json:"spawn,omitempty"`
}

type FeedbackInfo struct {
	Type     string `json:"type"`
	Username string `json:"username,omitempty"`
	Target   string `json:"target,omitempty"`
	Headshot bool   `json:"headshot,omitempty"`
	Time     string `json:"time,omitempty"`
}

func buildOutput(reader *dissect.Reader, rawData []byte, headerOnly bool) FullOutput {
	// Extract header info
	header := HeaderInfo{
		GameVersion: reader.Header.GameVersion,
		MatchID:     reader.Header.MatchID,
		RoundNumber: reader.Header.RoundNumber,
	}

	// Map name
	if reader.Header.Map != 0 {
		header.MapName = reader.Header.Map.String()
	}

	// Game mode
	if reader.Header.GameMode != 0 {
		header.GameMode = reader.Header.GameMode.String()
	}

	// Teams
	for _, t := range reader.Header.Teams {
		role := ""
		if t.Role == dissect.Attack {
			role = "Attack"
		} else if t.Role == dissect.Defense {
			role = "Defense"
		}
		header.Teams = append(header.Teams, TeamInfo{
			Name:  t.Name,
			Score: t.Score,
			Won:   t.Won,
			Role:  role,
		})
	}

	// Players
	for _, p := range reader.Header.Players {
		isAttack := false
		if p.TeamIndex < len(reader.Header.Teams) {
			isAttack = reader.Header.Teams[p.TeamIndex].Role == dissect.Attack
		}
		ph := PlayerInfoHeader{
			Username:  p.Username,
			Operator:  p.Operator.String(),
			TeamIndex: p.TeamIndex,
			IsAttack:  isAttack,
			Spawn:     p.Spawn,
		}
		if p.InitialOperator != 0 {
			ph.InitialOperator = p.InitialOperator.String()
		}
		header.Players = append(header.Players, ph)
	}

	// Match feedback
	for _, mf := range reader.MatchFeedback {
		hs := false
		if mf.Headshot != nil {
			hs = *mf.Headshot
		}
		fb := FeedbackInfo{
			Type:     mf.Type.String(),
			Username: mf.Username,
			Target:   mf.Target,
			Headshot: hs,
			Time:     mf.Time,
		}
		header.MatchFeedback = append(header.MatchFeedback, fb)
	}

	output := FullOutput{Header: header}

	if headerOnly {
		return output
	}

	// Run binary analysis
	if len(rawData) > 0 {
		players := make([]analysis.PlayerInfo, len(header.Players))
		for i, p := range header.Players {
			players[i] = analysis.PlayerInfo{
				Username:  p.Username,
				Operator:  p.Operator,
				TeamIndex: p.TeamIndex,
				IsAttack:  p.IsAttack,
			}
		}

		// Extract entity->player mapping from dissect library's PositionUpdates
		entityToPlayer := make(map[uint32]int)
		for _, pu := range reader.PositionUpdates {
			if pu.PlayerIndex >= 0 && pu.PlayerIndex < len(players) {
				entityToPlayer[pu.EntityRef] = pu.PlayerIndex
			}
		}

		// Convert dissect library positions to analysis format
		libPositions := make([]analysis.LibraryPosition, len(reader.PositionUpdates))
		for i, pu := range reader.PositionUpdates {
			libPositions[i] = analysis.LibraryPosition{
				EntityRef:   pu.EntityRef,
				PlayerIndex: pu.PlayerIndex,
				X:           pu.X,
				Y:           pu.Y,
				Z:           pu.Z,
				Yaw:         pu.Yaw,
				Pitch:       pu.Pitch,
				IsDroneView: pu.IsDroneView,
				BinOffset:   pu.BinOffset,
			}
		}

		output.Analysis = analysis.AnalyzeRoundWithLibraryPositions(rawData, players, libPositions, entityToPlayer)

		// Populate operator swaps from the library's already-resolved MatchFeedback.
		// reconcileOperatorSwaps() (called inside reader.Read()) handles all season paths:
		// Y10S4+: header RoleName vs readPlayer operator, pre-Y9S3: DissectID, Y9S3+: uiID.
		usernameToIdx := make(map[string]int, len(header.Players))
		for i, p := range header.Players {
			usernameToIdx[p.Username] = i
		}

		// For Y10S4+ the library skips the binary event entirely so MatchFeedback has no
		// timing. Cross-reference with the binary scanner results (which DO have timing
		// via tick interpolation) using toOperator as the join key.
		binarySwapTime := make(map[string]float32)
		for _, bsw := range output.Analysis.OperatorSwaps {
			if bsw.ToOperator != "" && bsw.TimeSecs > 0 {
				binarySwapTime[bsw.ToOperator] = bsw.TimeSecs
			}
		}

		var libSwaps []analysis.OperatorSwapEvent
		for _, mf := range reader.MatchFeedback {
			if mf.Type != dissect.OperatorSwap {
				continue
			}
			pIdx, ok := usernameToIdx[mf.Username]
			if !ok {
				continue
			}
			from := ""
			if pIdx < len(header.Players) && header.Players[pIdx].InitialOperator != "" {
				from = header.Players[pIdx].InitialOperator
			}
			toName := mf.Operator.String()
			t := float32(mf.TimeInSeconds)
			if t == 0 {
				if bt, ok := binarySwapTime[toName]; ok {
					t = bt
				}
			}
			libSwaps = append(libSwaps, analysis.OperatorSwapEvent{
				PlayerIndex:  pIdx,
				Username:     mf.Username,
				FromOperator: from,
				ToOperator:   toName,
				TimeSecs:     t,
			})
		}
		output.Analysis.OperatorSwaps = libSwaps

		// Build tick elapsed map once for reuse across event arrays
		tickElapsed := analysis.BuildTickElapsedMap(output.Analysis.TimerTicks, output.Analysis.RoundDuration)

		// Score delta events — already fully parsed by the library
		for _, su := range reader.ScoreUpdates {
			output.Analysis.ScoreUpdates = append(output.Analysis.ScoreUpdates, analysis.ScoreUpdateEvent{
				PlayerIndex: su.PlayerIndex,
				Username:    su.Username,
				PrevScore:   su.PrevScore,
				NewScore:    su.NewScore,
				Delta:       su.Delta,
				TimeSecs:    float32(tickElapsed(int64(su.BinOffset))),
				BinOffset:   su.BinOffset,
			})
		}

		// Drone lifecycle events — map Seq → BinOffset via PositionUpdates, then interpolate
		posLen := len(reader.PositionUpdates)
		for _, de := range reader.DroneEvents {
			binOff := int64(0)
			if de.Seq >= 0 && de.Seq < posLen {
				binOff = int64(reader.PositionUpdates[de.Seq].BinOffset)
			}
			output.Analysis.DroneEvents = append(output.Analysis.DroneEvents, analysis.DroneEventEntry{
				PlayerRef: de.PlayerRef,
				DroneRef:  de.DroneRef,
				Seq:       de.Seq,
				Connect:   de.Connect,
				TimeSecs:  float32(tickElapsed(binOff)),
			})
		}

		// Death timings — last significant movement position for each player who died
		for _, dt := range reader.DeathTimings {
			output.Analysis.DeathTimings = append(output.Analysis.DeathTimings, analysis.DeathTimingEntry{
				PlayerIndex:         dt.PlayerIndex,
				LastMovementSeq:     dt.LastMovementSeq,
				LastMovementTimeSec: dt.LastMovementTime,
				LastX:               dt.LastX,
				LastY:               dt.LastY,
				LastZ:               dt.LastZ,
			})
		}
	}

	return output
}
