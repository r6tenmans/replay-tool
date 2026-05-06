// healthdump: dump every TLV around each health-update marker. Look for
// hitCounter / damageRate fields that may not be co-located with the hp event.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/wnc-replay/replay-tool/dissect"
)

const (
	healthHash     uint32 = 0x4171D3C3
	maxHealthHash  uint32 = 0xC2D846F8
	damageRateHash uint32 = 0x475BB68B
	hitCounterHash uint32 = 0xF634093A
	healthTimeHash uint32 = 0x848F67CF
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: healthdump <file.rec>")
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
	_ = r

	// Step 1: count where each sub-property hash appears, ignoring proximity to hp.
	allOccs := map[uint32]int{
		healthHash:     0,
		maxHealthHash:  0,
		damageRateHash: 0,
		hitCounterHash: 0,
		healthTimeHash: 0,
	}
	allOffsets := map[uint32][]int{}
	for i := 0; i+8 <= len(data); i++ {
		h := binary.LittleEndian.Uint32(data[i : i+4])
		if _, want := allOccs[h]; want {
			allOccs[h]++
			if len(allOffsets[h]) < 5 {
				allOffsets[h] = append(allOffsets[h], i)
			}
		}
	}
	fmt.Println("=== Sub-property hash occurrence counts ===")
	for h, c := range allOccs {
		fmt.Printf("  0x%08X count=%d firstOffsets=%v\n", h, c, allOffsets[h])
	}
	fmt.Println()

	// Step 2: For each healthHash hit, dump the unique sub-property hashes seen
	// within a 2KB window (8x bigger than the PR's 256). See if hitCounter is
	// just farther away than 256 bytes.
	const window = 2048
	hashGroups := []struct{ h uint32; name string }{
		{maxHealthHash, "maxHP"},
		{damageRateHash, "dmgRate"},
		{hitCounterHash, "hitCnt"},
		{healthTimeHash, "hpTime"},
	}
	totalHP := 0
	hitInWindow := map[string]int{}
	for i := 0; i+8 <= len(data); i++ {
		h := binary.LittleEndian.Uint32(data[i : i+4])
		if h != healthHash {
			continue
		}
		hp := math.Float32frombits(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		if hp < 0 || hp > 200 {
			continue
		}
		totalHP++
		// Track which sub-property hashes appear within +/-window
		start := i - window
		if start < 0 {
			start = 0
		}
		end := i + window
		if end+8 > len(data) {
			end = len(data) - 8
		}
		for j := start; j+8 <= end; j++ {
			h2 := binary.LittleEndian.Uint32(data[j : j+4])
			for _, hg := range hashGroups {
				if h2 == hg.h {
					hitInWindow[hg.name]++
					break // one count per hp event per hash
				}
			}
		}
	}
	fmt.Printf("Total health-hash events: %d\n", totalHP)
	fmt.Println("Sub-property occurrences within +/-2KB of a health event:")
	for _, hg := range hashGroups {
		fmt.Printf("  %-10s = %d\n", hg.name, hitInWindow[hg.name])
	}
	fmt.Println()

	// Step 3: For the first 5 hp events, dump the absolute distance to each sub-prop.
	fmt.Println("=== First 5 health events: distances to sub-properties ===")
	count := 0
	for i := 0; i+8 <= len(data); i++ {
		h := binary.LittleEndian.Uint32(data[i : i+4])
		if h != healthHash {
			continue
		}
		hp := math.Float32frombits(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		if hp < 0 || hp > 200 {
			continue
		}
		count++
		if count > 5 {
			break
		}
		fmt.Printf("  hp event @%d (hp=%.2f)\n", i, hp)
		for _, hg := range hashGroups {
			// Find nearest occurrence
			best := -1
			bestDist := -1
			for j := i - 4096; j < i+4096; j++ {
				if j < 0 || j+4 > len(data) {
					continue
				}
				h2 := binary.LittleEndian.Uint32(data[j : j+4])
				if h2 == hg.h {
					d := j - i
					if d < 0 {
						d = -d
					}
					if best < 0 || d < bestDist {
						best = j
						bestDist = d
					}
				}
			}
			if best >= 0 {
				v := math.Float32frombits(binary.LittleEndian.Uint32(data[best+4 : best+8]))
				fmt.Printf("    %-10s @%+d (dist=%d) value=%.4f\n", hg.name, best-i, bestDist, v)
			} else {
				fmt.Printf("    %-10s NOT FOUND within +/-4KB\n", hg.name)
			}
		}
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
