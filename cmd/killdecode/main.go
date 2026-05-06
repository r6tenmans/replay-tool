// killdecode: dump every TLV around each kill marker, correlate with known
// kill metadata (headshot, attacker, victim) to decode what each enum means.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"

	"github.com/wnc-replay/replay-tool/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: killdecode <file.rec>")
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

	killSig := []byte{0x22, 0xD9, 0x13, 0x3C, 0xBA}

	// Helper to find player by username
	playerIdx := func(name string) int {
		for i, p := range r.Header.Players {
			if p.Username == name {
				return i
			}
		}
		return -1
	}

	// Find all kill marker offsets and parse attacker/target.
	type killMeta struct {
		off       int
		attacker  string
		target    string
		atkIdx    int
		vicIdx    int
		atkOp     string
		vicOp     string
		atkAtk    bool // attacker was on Attack team
		vicAtk    bool
		headshot  bool
		isDBNO    bool
		feedback  *dissect.MatchUpdate
	}
	var kills []killMeta

	for i := 0; i+5 < len(data); i++ {
		if !bytes.Equal(data[i:i+5], killSig) {
			continue
		}
		off := i + 5
		if off >= len(data) {
			continue
		}
		alen := int(data[off])
		off++
		if alen > 64 || off+alen > len(data) {
			continue
		}
		atk := string(data[off : off+alen])
		off += alen + 15
		if off >= len(data) {
			continue
		}
		tlen := int(data[off])
		off++
		if tlen > 64 || off+tlen > len(data) {
			continue
		}
		vic := string(data[off : off+tlen])
		off += tlen + 56
		if off >= len(data) {
			continue
		}
		hs := data[off] == 1
		if !isAscii(vic) || (atk != "" && !isAscii(atk)) {
			continue
		}

		ai, vi := playerIdx(atk), playerIdx(vic)
		atkOp := "?"
		vicOp := "?"
		atkOnAtk := false
		vicOnAtk := false
		if ai >= 0 {
			atkOp = r.Header.Players[ai].Operator.String()
			ti := r.Header.Players[ai].TeamIndex
			if ti < len(r.Header.Teams) {
				atkOnAtk = r.Header.Teams[ti].Role == dissect.Attack
			}
		}
		if vi >= 0 {
			vicOp = r.Header.Players[vi].Operator.String()
			ti := r.Header.Players[vi].TeamIndex
			if ti < len(r.Header.Teams) {
				vicOnAtk = r.Header.Teams[ti].Role == dissect.Attack
			}
		}
		// Find matching MatchFeedback entry
		var fb *dissect.MatchUpdate
		for k := range r.MatchFeedback {
			mf := &r.MatchFeedback[k]
			if mf.Username == atk && mf.Target == vic && (mf.Type == dissect.Kill || mf.Type == dissect.DBNO) {
				fb = mf
				break
			}
		}
		kills = append(kills, killMeta{i, atk, vic, ai, vi, atkOp, vicOp, atkOnAtk, vicOnAtk, hs, false, fb})
	}

	// Dedupe by attacker→target
	seen := map[string]bool{}
	var deduped []killMeta
	for _, k := range kills {
		key := k.attacker + "|" + k.target
		if seen[key] {
			continue
		}
		seen[key] = true
		deduped = append(deduped, k)
	}
	kills = deduped

	fmt.Printf("Found %d unique kill events\n\n", len(kills))

	// For each kill, dump every TLV (0x22/0x23 marker) within ±256 bytes.
	for _, k := range kills {
		fmt.Printf("=== %s -> %s (atk_op=%s, vic_op=%s, hs=%v, atkSide=%s, vicSide=%s) ===\n",
			k.attacker, k.target, k.atkOp, k.vicOp, k.headshot,
			boolStr(k.atkAtk, "Atk", "Def"), boolStr(k.vicAtk, "Atk", "Def"))
		dumpTLVs(data, k.off, 256)
		fmt.Println()
	}
}

// dumpTLVs prints every 0x22 / 0x23 marker hash + value within window of center.
func dumpTLVs(data []byte, center, window int) {
	start := center - window
	if start < 0 {
		start = 0
	}
	end := center + window
	if end+13 > len(data) {
		end = len(data) - 13
	}
	hashes := make(map[uint32][]string) // hash -> list of "type:value" strings
	for j := start; j+9 < end; j++ {
		if data[j] != 0x22 && data[j] != 0x23 {
			continue
		}
		h := binary.LittleEndian.Uint32(data[j+1 : j+5])
		typeByte := data[j+5]
		var val string
		switch typeByte {
		case 0x01:
			if j+7 <= len(data) {
				val = fmt.Sprintf("u8=%d", data[j+6])
			}
		case 0x04:
			if j+10 <= len(data) {
				v := binary.LittleEndian.Uint32(data[j+6 : j+10])
				val = fmt.Sprintf("u32=%d (0x%X) f32=%g", v, v, math.Float32frombits(v))
			}
		case 0x08:
			if j+14 <= len(data) {
				val = fmt.Sprintf("u64=%d (0x%X)", binary.LittleEndian.Uint64(data[j+6:j+14]),
					binary.LittleEndian.Uint64(data[j+6:j+14]))
			}
		default:
			val = fmt.Sprintf("type=0x%02X", typeByte)
		}
		hashes[h] = append(hashes[h], fmt.Sprintf("@%d %s", j-center, val))
	}
	// Sort by hash for stable output
	type entry struct {
		h    uint32
		vals []string
	}
	var rows []entry
	for h, v := range hashes {
		rows = append(rows, entry{h, v})
	}
	for _, r := range rows {
		// Skip super-common ones (string-related, often noise)
		if r.h == 0 || r.h == 0xFFFFFFFF {
			continue
		}
		fmt.Printf("  0x%08X: %v\n", r.h, r.vals)
	}
}

func isAscii(s string) bool {
	for _, c := range s {
		if c < 0x20 || c >= 0x7F {
			return false
		}
	}
	return len(s) > 0
}

func boolStr(b bool, t, f string) string {
	if b {
		return t
	}
	return f
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
