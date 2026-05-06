// enumstats: walk every .rec file under given directories, extract kill events
// with their full extended TLV set, and aggregate distributions to decode
// killEnum1, killEnum5, and the weaponEntRef64 sentinel.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/wnc-replay/replay-tool/dissect"
)

// Hashes from PR #1 + decoded values
const (
	kHashWeaponEntRef64 uint32 = 0x790009E3
	kHashKillFlag1      uint32 = 0x8F0292B5
	kHashKillEnum1      uint32 = 0x5BC4BC84
	kHashKillEnum2      uint32 = 0x37BF3E90
	kHashKillEnum3      uint32 = 0xD13DA88D
	kHashKillEnum4      uint32 = 0x3187B853
	kHashKillEnum5      uint32 = 0x0B64ADA5
	kHashWeaponID       uint32 = 0x65DD6CF8
	kHashHeadshot       uint32 = 0x4EA45BC3
)

type killRow struct {
	file       string
	gameVer    string
	atkOp      string
	vicOp      string
	atkAtk     bool
	vicAtk     bool
	headshot   bool
	weaponRef  uint64 // 0x790009E3
	flag1      uint8  // 0x8F0292B5
	enum1      uint32 // 0x5BC4BC84
	enum5      uint32 // 0x0B64ADA5
	weaponID   uint64 // 0x65DD6CF8
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: enumstats <root-dir> [<root-dir>...]")
		os.Exit(1)
	}

	var rows []killRow
	totalFiles := 0
	failedFiles := 0

	for _, root := range os.Args[1:] {
		filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return nil
			}
			if !strings.HasSuffix(strings.ToLower(path), ".rec") {
				return nil
			}
			if strings.Contains(path, "invalid") || strings.Contains(path, "corrupted") || strings.Contains(path, "not_zstd") {
				return nil
			}
			totalFiles++
			fileRows, err := scanFile(path)
			if err != nil {
				failedFiles++
				return nil
			}
			rows = append(rows, fileRows...)
			return nil
		})
	}

	fmt.Printf("Scanned %d .rec files (%d failed). Total kill events: %d\n\n", totalFiles, failedFiles, len(rows))

	// === weaponEntRef64 distribution ===
	fmt.Println("=== weaponEntRef64 (hash 0x790009E3) distribution ===")
	wepRefDist := make(map[uint64]int)
	for _, r := range rows {
		wepRefDist[r.weaponRef]++
	}
	type wrCount struct {
		v uint64
		c int
	}
	var wrSorted []wrCount
	for v, c := range wepRefDist {
		wrSorted = append(wrSorted, wrCount{v, c})
	}
	sort.Slice(wrSorted, func(i, j int) bool { return wrSorted[i].c > wrSorted[j].c })
	for i, w := range wrSorted {
		if i >= 12 {
			break
		}
		label := ""
		if w.v == 0xFFFFFFFFFFFFFFFF {
			label = " (all-ones sentinel)"
		} else if w.v == 0 {
			label = " (zero/missing)"
		}
		fmt.Printf("  0x%016X count=%d%s\n", w.v, w.c, label)
	}
	fmt.Printf("  Total unique values: %d\n", len(wepRefDist))
	fmt.Println()

	// === killEnum1 distribution + cross-tab with attacker/victim/HS ===
	fmt.Println("=== killEnum1 (hash 0x5BC4BC84) distribution ===")
	enum1Dist := make(map[uint32]int)
	for _, r := range rows {
		enum1Dist[r.enum1]++
	}
	var e1Sorted []wrCount
	for v, c := range enum1Dist {
		e1Sorted = append(e1Sorted, wrCount{uint64(v), c})
	}
	sort.Slice(e1Sorted, func(i, j int) bool { return e1Sorted[i].c > e1Sorted[j].c })
	for _, w := range e1Sorted {
		fmt.Printf("  enum1=%d count=%d\n", w.v, w.c)
	}
	fmt.Println()

	fmt.Println("=== killEnum1 cross-tab with attacker side (D=defender, A=attacker) and headshot ===")
	type ctKey struct {
		atkSide string
		vicSide string
		hs      bool
	}
	ctEnum1 := make(map[ctKey]map[uint32]int)
	for _, r := range rows {
		k := ctKey{boolStr(r.atkAtk, "A", "D"), boolStr(r.vicAtk, "A", "D"), r.headshot}
		if ctEnum1[k] == nil {
			ctEnum1[k] = make(map[uint32]int)
		}
		ctEnum1[k][r.enum1]++
	}
	for k, dist := range ctEnum1 {
		hsLabel := "body"
		if k.hs {
			hsLabel = "HS"
		}
		fmt.Printf("  atk=%s vic=%s %s:", k.atkSide, k.vicSide, hsLabel)
		for v, c := range dist {
			fmt.Printf(" enum1=%d:%d", v, c)
		}
		fmt.Println()
	}
	fmt.Println()

	// === killEnum1 by attacker operator ===
	fmt.Println("=== killEnum1 by attacker operator (top 12) ===")
	opEnum1 := make(map[string]map[uint32]int)
	opCount := make(map[string]int)
	for _, r := range rows {
		if opEnum1[r.atkOp] == nil {
			opEnum1[r.atkOp] = make(map[uint32]int)
		}
		opEnum1[r.atkOp][r.enum1]++
		opCount[r.atkOp]++
	}
	type opKV struct {
		op string
		c  int
	}
	var opSorted []opKV
	for op, c := range opCount {
		opSorted = append(opSorted, opKV{op, c})
	}
	sort.Slice(opSorted, func(i, j int) bool { return opSorted[i].c > opSorted[j].c })
	for i, kv := range opSorted {
		if i >= 12 {
			break
		}
		fmt.Printf("  %-20s n=%-3d  ", kv.op, kv.c)
		for v, c := range opEnum1[kv.op] {
			fmt.Printf("enum1=%d:%d ", v, c)
		}
		fmt.Println()
	}
	fmt.Println()

	// === killEnum5 distribution (expected: always 0) ===
	fmt.Println("=== killEnum5 (hash 0x0B64ADA5) distribution ===")
	enum5Dist := make(map[uint32]int)
	for _, r := range rows {
		enum5Dist[r.enum5]++
	}
	var e5Sorted []wrCount
	for v, c := range enum5Dist {
		e5Sorted = append(e5Sorted, wrCount{uint64(v), c})
	}
	sort.Slice(e5Sorted, func(i, j int) bool { return e5Sorted[i].c > e5Sorted[j].c })
	for _, w := range e5Sorted {
		fmt.Printf("  enum5=%d count=%d\n", w.v, w.c)
	}
	fmt.Println()

	// === flag1 distribution (expected: always 0) ===
	fmt.Println("=== killFlag1 (hash 0x8F0292B5) distribution ===")
	flag1Dist := make(map[uint8]int)
	for _, r := range rows {
		flag1Dist[r.flag1]++
	}
	for v, c := range flag1Dist {
		fmt.Printf("  flag1=%d count=%d\n", v, c)
	}
	fmt.Println()

	// === Game version breakdown (which Y10/Y11 versions had these TLVs) ===
	fmt.Println("=== Kill events by game version ===")
	verCount := make(map[string]int)
	for _, r := range rows {
		verCount[r.gameVer]++
	}
	for v, c := range verCount {
		fmt.Printf("  %-22s %d kills\n", v, c)
	}
	fmt.Println()

	// === weaponEntRef64 cross-tab by version (test sentinel vs zero hypothesis) ===
	fmt.Println("=== weaponEntRef64 by version (sentinel=0xFFF.. vs zero=0x000..) ===")
	type vKey struct {
		ver  string
		isFF bool
	}
	verRefDist := make(map[vKey]int)
	for _, r := range rows {
		verRefDist[vKey{r.gameVer, r.weaponRef == 0xFFFFFFFFFFFFFFFF}]++
	}
	for k, c := range verRefDist {
		label := "zero"
		if k.isFF {
			label = "sentinel"
		}
		fmt.Printf("  %-22s %s: %d\n", k.ver, label, c)
	}
	fmt.Println()

	// === killEnum1 by version ===
	fmt.Println("=== killEnum1 by version ===")
	type ve1Key struct {
		ver string
		v   uint32
	}
	ve1 := make(map[ve1Key]int)
	for _, r := range rows {
		ve1[ve1Key{r.gameVer, r.enum1}]++
	}
	for k, c := range ve1 {
		fmt.Printf("  %-22s enum1=%d: %d\n", k.ver, k.v, c)
	}
}

func scanFile(path string) ([]killRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r, err := dissect.NewReader(f)
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	r.Write(&buf)
	data := buf.Bytes()
	r.Read()

	playerByName := make(map[string]int, len(r.Header.Players))
	for i, p := range r.Header.Players {
		playerByName[p.Username] = i
	}

	killSig := []byte{0x22, 0xD9, 0x13, 0x3C, 0xBA}
	var rows []killRow
	gameVer := r.Header.GameVersion

	seen := make(map[string]bool)
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
		key := atk + "|" + vic
		if seen[key] {
			continue
		}
		seen[key] = true

		row := killRow{
			file:     filepath.Base(path),
			gameVer:  gameVer,
			headshot: hs,
		}
		if ai, ok := playerByName[atk]; ok && ai < len(r.Header.Players) {
			row.atkOp = r.Header.Players[ai].Operator.String()
			ti := r.Header.Players[ai].TeamIndex
			if ti < len(r.Header.Teams) {
				row.atkAtk = r.Header.Teams[ti].Role == dissect.Attack
			}
		}
		if vi, ok := playerByName[vic]; ok && vi < len(r.Header.Players) {
			row.vicOp = r.Header.Players[vi].Operator.String()
			ti := r.Header.Players[vi].TeamIndex
			if ti < len(r.Header.Teams) {
				row.vicAtk = r.Header.Teams[ti].Role == dissect.Attack
			}
		}

		// Scan TLVs in 256-byte window
		fillTLVs(data, i, &row)
		rows = append(rows, row)
	}
	return rows, nil
}

func fillTLVs(data []byte, killOff int, row *killRow) {
	const window = 256
	start := killOff - window
	if start < 0 {
		start = 0
	}
	end := killOff + window
	if end+13 > len(data) {
		end = len(data) - 13
	}
	var have struct {
		w, f, e1, e5, wid bool
	}
	for j := start; j+9 < end; j++ {
		if data[j] != 0x22 && data[j] != 0x23 {
			continue
		}
		h := binary.LittleEndian.Uint32(data[j+1 : j+5])
		typeByte := data[j+5]
		switch h {
		case kHashWeaponEntRef64:
			if !have.w && typeByte == 0x08 && j+14 <= len(data) {
				row.weaponRef = binary.LittleEndian.Uint64(data[j+6 : j+14])
				have.w = true
			}
		case kHashKillFlag1:
			if !have.f && typeByte == 0x01 && j+7 <= len(data) {
				row.flag1 = data[j+6]
				have.f = true
			}
		case kHashKillEnum1:
			if !have.e1 && typeByte == 0x04 && j+10 <= len(data) {
				row.enum1 = binary.LittleEndian.Uint32(data[j+6 : j+10])
				have.e1 = true
			}
		case kHashKillEnum5:
			if !have.e5 && typeByte == 0x04 && j+10 <= len(data) {
				row.enum5 = binary.LittleEndian.Uint32(data[j+6 : j+10])
				have.e5 = true
			}
		case kHashWeaponID:
			if !have.wid && typeByte == 0x08 && j+14 <= len(data) {
				row.weaponID = binary.LittleEndian.Uint64(data[j+6 : j+14])
				have.wid = true
			}
		}
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
