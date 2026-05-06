// deepscan: exhaustive byte-level survey to find real data we're inferring instead of decoding.
// Targets:
//   1. ALL float values in the health stream that look like HP (not just full/dbno/dead)
//   2. Property hashes that occur exactly once per kill (damage value candidate)
//   3. Plant/defuse marker bytes near MatchFeedback offsets
//   4. The exact byte that distinguishes operator-specific gadgets from universal ones
//   5. Session-variable weapon ID → entity ref binding
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: deepscan <file.rec>")
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
	fmt.Printf("Decompressed: %d bytes\n\n", len(data))

	// =========================================
	// 1. Find ALL float32 values that look like HP (0-130) following the health hash
	// =========================================
	healthHashLE := []byte{0xC3, 0xD3, 0x71, 0x41}
	hpHistogram := make(map[int]int) // bucketed: floor(hp)
	allHPs := []float32{}
	hpOffsets := []int{}
	for i := 0; i+8 <= len(data); i++ {
		if !equals4(data, i, healthHashLE) {
			continue
		}
		bits := binary.LittleEndian.Uint32(data[i+4 : i+8])
		hp := math.Float32frombits(bits)
		if math.IsNaN(float64(hp)) || math.IsInf(float64(hp), 0) {
			continue
		}
		if hp < 0 || hp > 200 {
			continue
		}
		hpHistogram[int(hp)]++
		allHPs = append(allHPs, hp)
		hpOffsets = append(hpOffsets, i)
	}
	fmt.Printf("=== Health-hash hits: %d ===\n", len(allHPs))
	type bucket struct {
		v, c int
	}
	var buckets []bucket
	for k, v := range hpHistogram {
		buckets = append(buckets, bucket{k, v})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].c > buckets[j].c })
	for i, b := range buckets {
		if i >= 20 {
			break
		}
		fmt.Printf("  hp~%-4d count=%d\n", b.v, b.c)
	}
	fmt.Println()

	// =========================================
	// 2. Look for damage values: float32 in 5-150 range right after a "shot" or "hit" hash.
	//    Hypothesis: there's a 4-byte hash (NOT 0x4171D3C3) that prefixes damage values.
	//    Strategy: for each 8-byte window where bytes 0-3 are a uint32 (potential hash) and
	//    bytes 4-7 are a float in (5,150), record the hash. Hashes with high frequency that
	//    aren't the health hash are likely damage/property fields.
	// =========================================
	fmt.Println("=== Hash candidates with float values in damage range (5-150) ===")
	hashWithFloat := make(map[uint32]int)
	hashFirstOff := make(map[uint32]int)
	for i := 0; i+8 <= len(data); i++ {
		h := binary.LittleEndian.Uint32(data[i : i+4])
		// Filter: high byte should be 0x40-0x42 (typical property hash prefix family) or
		// some specific ranges. Skip ASCII noise.
		hb := h >> 24
		if hb < 0x30 || hb > 0xF0 {
			continue
		}
		fb := math.Float32frombits(binary.LittleEndian.Uint32(data[i+4 : i+8]))
		if math.IsNaN(float64(fb)) || math.IsInf(float64(fb), 0) {
			continue
		}
		if fb < 5 || fb > 150 {
			continue
		}
		hashWithFloat[h]++
		if _, ok := hashFirstOff[h]; !ok {
			hashFirstOff[h] = i
		}
	}
	type hashStat struct {
		h        uint32
		c        int
		firstOff int
	}
	var stats []hashStat
	for h, c := range hashWithFloat {
		// Filter to event-frequency (5-200 hits) — too rare = noise, too common = generic.
		if c < 5 || c > 500 {
			continue
		}
		stats = append(stats, hashStat{h, c, hashFirstOff[h]})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].c < stats[j].c })
	fmt.Printf("Top candidates (5-500 hits, sorted by frequency ASC):\n")
	for i, s := range stats {
		if i >= 30 {
			break
		}
		// Only show hashes we don't already know
		known := []uint32{0x4171D3C3} // health
		isKnown := false
		for _, kh := range known {
			if s.h == kh {
				isKnown = true
				break
			}
		}
		if isKnown {
			continue
		}
		fmt.Printf("  0x%08X count=%-4d firstOff=%-10d (%.1fMB)\n", s.h, s.c, s.firstOff, float64(s.firstOff)/1e6)
	}
	fmt.Println()

	// =========================================
	// 3. Look for ASCII strings related to bomb plant/defuse anywhere in the binary.
	// =========================================
	fmt.Println("=== ASCII strings (entire binary, filtered to interesting keywords) ===")
	{
		strs := findStringsInRegion(data, 0, len(data), 8)
		shown := 0
		seen := make(map[string]bool)
		for _, s := range strs {
			if seen[s] {
				continue
			}
			seen[s] = true
			if shown >= 80 {
				break
			}
			low := strings.ToLower(s)
			if strings.Contains(low, "plant") || strings.Contains(low, "defuse") ||
				strings.Contains(low, "bomb") || strings.Contains(low, "objective") ||
				strings.Contains(low, "found") || strings.Contains(low, "killed") ||
				strings.Contains(low, "destroy") || strings.Contains(low, "round") ||
				strings.Contains(low, "win") || strings.Contains(low, "swap") ||
				strings.Contains(low, "operator") || strings.Contains(low, "battleye") {
				fmt.Printf("  %s\n", s)
				shown++
			}
		}
	}
	fmt.Println()

	// =========================================
	// 4. Find session-variable weapon hashes by entity-ref ownership.
	//    For each ammo update event in the library, the weapon entity ref tells us
	//    which weapon slot it represents. The hash IDs near each weapon ref in the
	//    binary should correlate with the operator's loadout.
	// =========================================
	fmt.Println("=== Ammo updates: weapon ref → first 32 bytes around it (loadout fingerprint) ===")
	type weaponRef struct {
		ref       uint32
		playerIdx int
		count     int
	}
	weaponRefs := make(map[uint32]*weaponRef)
	for _, au := range r.AmmoUpdates {
		if au.PlayerIndex < 0 {
			continue
		}
		// AmmoUpdate doesn't expose weaponRef directly, but we can search backward from
		// BinOffset for a uint32 with high byte >= 0xF0.
		bo := au.BinOffset
		if bo < 16 {
			continue
		}
		// Scan back 32 bytes
		var ref uint32
		for j := bo - 4; j >= bo-32 && j >= 0; j-- {
			cand := binary.LittleEndian.Uint32(data[j : j+4])
			if cand>>24 >= 0xF0 {
				ref = cand
				break
			}
		}
		if ref == 0 {
			continue
		}
		if _, ok := weaponRefs[ref]; !ok {
			weaponRefs[ref] = &weaponRef{ref: ref, playerIdx: au.PlayerIndex}
		}
		weaponRefs[ref].count++
	}
	fmt.Printf("  Unique weapon refs: %d\n", len(weaponRefs))
	type refSorted struct {
		ref       uint32
		playerIdx int
		count     int
	}
	var refs []refSorted
	for _, wr := range weaponRefs {
		refs = append(refs, refSorted{wr.ref, wr.playerIdx, wr.count})
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].playerIdx < refs[j].playerIdx })
	for _, wr := range refs {
		if wr.count < 5 {
			continue // skip rare refs (maybe gadgets)
		}
		username := "?"
		op := "?"
		if wr.playerIdx >= 0 && wr.playerIdx < len(r.Header.Players) {
			username = r.Header.Players[wr.playerIdx].Username
			op = r.Header.Players[wr.playerIdx].Operator.String()
		}
		fmt.Printf("  player[%d]=%s (%s) ref=0x%08X count=%d\n", wr.playerIdx, username, op, wr.ref, wr.count)
	}
	fmt.Println()

	// =========================================
	// 5. Cross-reference loadout block sg hashes with operator-secondary-list to
	//    find which sg hash corresponds to which gadget. Look for the slotSecondaryGadget
	//    auxHash (0xAFB455D8) and dump the 8 bytes BEFORE it (the gadget gameID) for each player.
	// =========================================
	fmt.Println("=== slotSecondaryGadget anchors: gameID followed by auxHash 0xAFB455D8 ===")
	sgAuxBytes := []byte{0xD8, 0x55, 0xB4, 0xAF}
	sgFirstOcc := []int{}
	for i := 8; i+4 <= len(data); i++ {
		if !equals4(data, i, sgAuxBytes) {
			continue
		}
		// Skip if we've already found 20 (we only need first batch — the loadout block)
		if len(sgFirstOcc) >= 20 {
			break
		}
		gameID := binary.LittleEndian.Uint64(data[i-8 : i])
		// Filter: gameID looks valid (high bytes 0)
		if gameID == 0 || (gameID>>40) != 0 {
			continue
		}
		sgFirstOcc = append(sgFirstOcc, i)
		fmt.Printf("  off=%d gameID=0x%X\n", i, gameID)
	}
	fmt.Println()

	// =========================================
	// 6. Look for plant/defuse via "DefuserPlant" / "PlantDefuser" / numeric event IDs.
	//    The dissect library uses numeric MatchUpdateType (Kill=0, DefuserPlantStart=2, etc).
	//    Look for a marker byte sequence we don't yet recognize.
	// =========================================
	fmt.Println("=== Looking for numeric event IDs near kill markers ===")
	killSig := []byte{0x22, 0xd9, 0x13, 0x3c, 0xba}
	killOffs := findAll(data, killSig)
	fmt.Printf("  kill markers: %d\n", len(killOffs))
	// For each kill marker, the byte BEFORE the 0x22 might be the event-type discriminator.
	if len(killOffs) > 0 {
		prevByteCounts := make(map[byte]int)
		for _, ko := range killOffs {
			if ko == 0 {
				continue
			}
			prevByteCounts[data[ko-1]]++
		}
		for b, c := range prevByteCounts {
			fmt.Printf("    byte-before-kill-marker: 0x%02X count=%d\n", b, c)
		}
	}
}

// ---------- helpers ----------

func equals4(d []byte, i int, p []byte) bool {
	return d[i] == p[0] && d[i+1] == p[1] && d[i+2] == p[2] && d[i+3] == p[3]
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

func findStringsInRegion(data []byte, start, end, minLen int) []string {
	var strs []string
	cur := strings.Builder{}
	for i := start; i < end; i++ {
		b := data[i]
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

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
