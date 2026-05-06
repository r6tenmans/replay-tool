// probe: hunt for high-value patterns we're not yet decoding.
// Focuses on the kill-feedback region (61.9MB+) where most game events live,
// and looks for known signatures around match-feedback offsets to find new ones.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/wnc-replay/replay-tool/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: probe <file.rec>")
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	must(err)
	defer f.Close()
	r, err := dissect.NewReader(f)
	must(err)
	var buf bytes.Buffer
	r.Write(&buf)
	data := buf.Bytes()
	r.Read()

	fmt.Printf("Decompressed: %d bytes\n", len(data))
	fmt.Printf("Round duration (binary feedback range): scanning...\n\n")

	// 1. Look at the kill-feedback region. We have 7 kills in MatchFeedback. Find each
	// and dump bytes after the kill marker to see if there's plant/defuse/other signals nearby.
	fmt.Println("=== Kill marker neighborhood (looking for unknown event signatures) ===")
	killSig := []byte{0x22, 0xd9, 0x13, 0x3c, 0xba} // "killIndicator" from feedback.go
	killOffsets := findAll(data, killSig)
	fmt.Printf("Found %d kill markers in binary\n", len(killOffsets))
	if len(killOffsets) > 0 {
		fmt.Printf("First kill marker offset: %d (= %.1fMB)\n", killOffsets[0], float64(killOffsets[0])/1e6)
		fmt.Printf("Last kill marker offset: %d (= %.1fMB)\n", killOffsets[len(killOffsets)-1], float64(killOffsets[len(killOffsets)-1])/1e6)
	}
	fmt.Println()

	// 2. Look for ASCII operator names that might mark plant/defuse events
	fmt.Println("=== Searching for known event name strings ===")
	names := []string{"Plant", "Defuse", "DefuserPlant", "DefuserDisable", "Battleye", "PlayerLeave", "OperatorSwap", "LocateObjective"}
	for _, name := range names {
		hits := findAll(data, []byte(name))
		if len(hits) == 0 {
			fmt.Printf("  %-20s : not found\n", name)
		} else {
			fmt.Printf("  %-20s : %d hits, first at %d\n", name, len(hits), hits[0])
			start := hits[0] - 16
			end := hits[0] + 32
			if start < 0 {
				start = 0
			}
			if end > len(data) {
				end = len(data)
			}
			fmt.Printf("    ctx: %s\n", hexDump(data[start:end], hits[0]-start))
		}
	}
	fmt.Println()

	// 3. Look for "DEFUSE" / "PLANT" / "SET" / "DROP" / "PICK" related signatures by scanning
	// for distinctive 4-byte hashes that occur ~1-3 times per round (event-like frequency).
	fmt.Println("=== High-value 4-byte signature search (1-15 hits in 60-65MB region) ===")
	hashCount := make(map[uint32]int)
	hashFirstOff := make(map[uint32]int)
	region := struct{ start, end int }{60_000_000, 65_000_000}
	if region.end > len(data) {
		region.end = len(data)
	}
	if region.start >= len(data) {
		fmt.Println("  (region beyond file end — skipping)")
	} else {
		for i := region.start; i+4 <= region.end; i++ {
			h := binary.LittleEndian.Uint32(data[i : i+4])
			// Skip obvious non-hash values: too small or ASCII text
			if h < 0x10000000 || h > 0xF0000000 {
				continue
			}
			// Skip values that are mostly ASCII
			b0, b1, b2, b3 := byte(h), byte(h>>8), byte(h>>16), byte(h>>24)
			if isPrintable(b0) && isPrintable(b1) && isPrintable(b2) && isPrintable(b3) {
				continue
			}
			if _, ok := hashFirstOff[h]; !ok {
				hashFirstOff[h] = i
			}
			hashCount[h]++
		}
		// Sort by count, filter to event-frequency range (1-15)
		type hashStat struct {
			hash      uint32
			count     int
			firstOff  int
		}
		var stats []hashStat
		for h, c := range hashCount {
			if c >= 1 && c <= 15 {
				stats = append(stats, hashStat{h, c, hashFirstOff[h]})
			}
		}
		sort.Slice(stats, func(i, j int) bool { return stats[i].count > stats[j].count })
		// Filter further: only show "interesting" prefixed hashes (most game hashes start with 0x4_, 0x5_, 0x6_, 0xC_)
		shown := 0
		for _, s := range stats {
			if shown >= 25 {
				break
			}
			highByte := s.hash >> 24
			// Game property hashes commonly start with: 0xC3 (health), 0xEB (?), 0x4E (?), 0x55 (?), etc.
			// Filter to a reasonable shape
			if highByte != 0xC3 && highByte != 0xEB && highByte != 0x9B &&
				highByte != 0xAF && highByte != 0xD9 && highByte != 0xE3 &&
				highByte != 0x21 && highByte != 0x96 && highByte != 0xCE {
				continue
			}
			fmt.Printf("  hash=0x%08X count=%-3d firstOff=%d\n", s.hash, s.count, s.firstOff)
			shown++
		}
	}
	fmt.Println()

	// 4. Inspect the gap between kill markers — look for 2-3 byte transition signatures.
	if len(killOffsets) >= 2 {
		fmt.Println("=== Bytes BEFORE each kill marker (looking for shared event header) ===")
		for k, kof := range killOffsets {
			if k >= 5 {
				break
			}
			start := kof - 32
			if start < 0 {
				start = 0
			}
			fmt.Printf("  kill@%d: %s\n", kof, hexDump(data[start:kof+8], 32))
		}
	}
	fmt.Println()

	// 5. Recording player POV: the dissect library tracks camera frames.
	// Show the count of camera frames per (recording) player to see if they switched POV.
	fmt.Println("=== Recording-player camera frames distribution ===")
	camsByPlayer := make(map[int]int)
	for _, cf := range r.CameraFrames {
		camsByPlayer[cf.PlayerIndex]++
	}
	for p, c := range camsByPlayer {
		username := "?"
		if p >= 0 && p < len(r.Header.Players) {
			username = r.Header.Players[p].Username
		}
		fmt.Printf("  player[%d]=%-20s frames=%d\n", p, username, c)
	}
	fmt.Println()

	// 6. Look at unknown entity "frames=1" entities — see if they have any common bytes
	// near them in the binary.
	fmt.Println("=== Library TrackedEntities classification ===")
	typeCount := make(map[string]int)
	for _, te := range r.TrackedEntities {
		typeCount[string(te.Type)]++
	}
	for t, c := range typeCount {
		fmt.Printf("  %s: %d\n", t, c)
	}
}

func findAll(haystack, needle []byte) []int {
	var positions []int
	start := 0
	for {
		idx := bytes.Index(haystack[start:], needle)
		if idx < 0 {
			break
		}
		positions = append(positions, start+idx)
		start = start + idx + 1
	}
	return positions
}

func hexDump(data []byte, mark int) string {
	var sb bytes.Buffer
	for i, b := range data {
		if i == mark {
			sb.WriteString("[")
		}
		fmt.Fprintf(&sb, "%02X", b)
		if i == mark+4 {
			sb.WriteString("]")
		}
		if i < len(data)-1 {
			sb.WriteString(" ")
		}
	}
	return sb.String()
}

func isPrintable(b byte) bool {
	return b >= 0x20 && b < 0x7F
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
