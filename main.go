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

	"github.com/N4m-N4m/r6-replay-tool/analysis"
	"github.com/redraskal/r6-dissect/dissect"
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
	Username  string `json:"username"`
	Operator  string `json:"operator"`
	TeamIndex int    `json:"teamIndex"`
	IsAttack  bool   `json:"isAttack"`
	Spawn     string `json:"spawn,omitempty"`
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
		header.Players = append(header.Players, PlayerInfoHeader{
			Username:  p.Username,
			Operator:  p.Operator.String(),
			TeamIndex: p.TeamIndex,
			IsAttack:  isAttack,
			Spawn:     p.Spawn,
		})
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
			}
		}

		output.Analysis = analysis.AnalyzeRoundWithLibraryPositions(rawData, players, libPositions, entityToPlayer)
	}

	return output
}
