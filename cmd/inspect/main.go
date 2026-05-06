// Inspection tool to reverse engineer Y11 unknown hashes and entity types.
// Dumps context around mystery hashes, health values, and frames=1 entities.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"

	"github.com/wnc-replay/replay-tool/dissect"
)

// Mystery gadget hashes — populate as needed
var mysteryGadgets = []uint64{}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: inspect <file.rec>")
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
	fmt.Printf("Decompressed: %d bytes\n\n", len(data))

	// Read header to get player operator info
	r.Read()
	fmt.Println("=== Players (header) ===")
	for i, p := range r.Header.Players {
		atk := "Def"
		if p.TeamIndex < len(r.Header.Teams) && r.Header.Teams[p.TeamIndex].Role == dissect.Attack {
			atk = "Atk"
		}
		fmt.Printf("  [%d] %-20s %s %s\n", i, p.Username, atk, p.Operator)
	}
	fmt.Println()

	// Look for each mystery hash in the binary, dump context
	for _, hash := range mysteryGadgets {
		fmt.Printf("=== Hash 0x%X (uint64 LE) ===\n", hash)
		hashBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(hashBytes, hash)
		positions := findAll(data, hashBytes)
		fmt.Printf("  found at %d offsets\n", len(positions))
		for k, pos := range positions {
			if k >= 3 {
				fmt.Printf("  ... and %d more\n", len(positions)-3)
				break
			}
			start := pos - 32
			end := pos + 32
			if start < 0 {
				start = 0
			}
			if end > len(data) {
				end = len(data)
			}
			fmt.Printf("  off=%d ctx=%s\n", pos, hexDump(data[start:end], pos-start))
			// Look for nearby printable strings
			searchStart := pos - 256
			searchEnd := pos + 256
			if searchStart < 0 {
				searchStart = 0
			}
			if searchEnd > len(data) {
				searchEnd = len(data)
			}
			strs := findStrings(data[searchStart:searchEnd], 6)
			if len(strs) > 0 {
				fmt.Printf("    nearby strings: %v\n", strs[:min(5, len(strs))])
			}
		}
		fmt.Println()
	}

	// Health=1.38, 1.43 investigation: find pattern 0x4171D3C3 + float32 in (0,5)
	fmt.Println("=== Health hash (0x4171D3C3) low-value samples ===")
	healthHash := []byte{0xC3, 0xD3, 0x71, 0x41}
	lowCount := 0
	zeroCount := 0
	highCount := 0
	for i := 0; i+8 <= len(data); i++ {
		if !equals4(data, i, healthHash) {
			continue
		}
		hpBits := binary.LittleEndian.Uint32(data[i+4 : i+8])
		hp := math.Float32frombits(hpBits)
		if hp < 0 || hp > 130 {
			continue
		}
		if hp == 0 {
			zeroCount++
		} else if hp < 5 {
			lowCount++
			if lowCount <= 5 {
				start := i - 24
				end := i + 24
				if start < 0 {
					start = 0
				}
				if end > len(data) {
					end = len(data)
				}
				fmt.Printf("  hp=%.4f off=%d ctx=%s\n", hp, i, hexDump(data[start:end], i-start))
			}
		} else if hp >= 100 {
			highCount++
		}
	}
	fmt.Printf("  Total: zero=%d, lowSuspicious=%d, fullHealth=%d\n\n", zeroCount, lowCount, highCount)

	// Inspect "unknown" entities — find SPAWN counter pattern + entity ref pairs
	fmt.Println("=== SPAWN counter distribution (all occurrences) ===")
	pat := []byte{0x61, 0x73, 0x85, 0xFE}
	counterDist := make(map[uint16]int)
	entityCounters := make(map[uint32]map[uint16]int)
	totalMatches := 0
	for i := 16; i+10 < len(data); i++ {
		if !equals4(data, i, pat) {
			continue
		}
		totalMatches++
		entityRef := binary.LittleEndian.Uint32(data[i-12 : i-8])
		counter := uint16(data[i+8]) | uint16(data[i+9])<<8
		counterDist[counter]++
		if entityCounters[entityRef] == nil {
			entityCounters[entityRef] = make(map[uint16]int)
		}
		entityCounters[entityRef][counter]++
	}
	fmt.Printf("  total pattern matches: %d, unique entities: %d\n", totalMatches, len(entityCounters))
	type kv struct {
		k uint16
		v int
	}
	var sorted []kv
	for k, v := range counterDist {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].v > sorted[j].v })
	fmt.Printf("  All SPAWN counter values:\n")
	for _, p := range sorted {
		fmt.Printf("    counter=%-6d (0x%04X) count=%d\n", p.k, p.k, p.v)
	}
	// Now count entities by their PEAK counter (max counter value seen for that entity)
	fmt.Println("\n  Entities classified by their max-seen counter:")
	maxCountByEntity := make(map[uint16]int)
	zeroOnlyCount := 0
	for _, counters := range entityCounters {
		maxCounter := uint16(0)
		hasNonZero := false
		for c := range counters {
			if c > 0 {
				hasNonZero = true
				if c > maxCounter {
					maxCounter = c
				}
			}
		}
		if !hasNonZero {
			zeroOnlyCount++
			continue
		}
		maxCountByEntity[maxCounter]++
	}
	fmt.Printf("    entities with ONLY counter=0: %d\n", zeroOnlyCount)
	type kv2 struct {
		k uint16
		v int
	}
	var entCounters []kv2
	for k, v := range maxCountByEntity {
		entCounters = append(entCounters, kv2{k, v})
	}
	sort.Slice(entCounters, func(i, j int) bool { return entCounters[i].v > entCounters[j].v })
	for _, p := range entCounters {
		fmt.Printf("    max-counter=%-6d (0x%04X) entities=%d\n", p.k, p.k, p.v)
	}
	fmt.Println()
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

func findStrings(data []byte, minLen int) []string {
	var strs []string
	cur := strings.Builder{}
	for _, b := range data {
		if b >= 0x20 && b < 0x7F {
			cur.WriteByte(b)
		} else {
			if cur.Len() >= minLen {
				strs = append(strs, cur.String())
			}
			cur.Reset()
		}
	}
	if cur.Len() >= minLen {
		strs = append(strs, cur.String())
	}
	return strs
}

func hexDump(data []byte, mark int) string {
	var sb strings.Builder
	for i, b := range data {
		if i == mark {
			sb.WriteString("[")
		}
		fmt.Fprintf(&sb, "%02X", b)
		if i == mark+7 {
			sb.WriteString("]")
		}
		if i < len(data)-1 {
			sb.WriteString(" ")
		}
	}
	return sb.String()
}

func equals4(data []byte, off int, pat []byte) bool {
	return data[off] == pat[0] && data[off+1] == pat[1] && data[off+2] == pat[2] && data[off+3] == pat[3]
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
