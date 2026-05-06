// sesweapon: trace session-variable weapon IDs (0x38C8D6, 0x57E038, etc.) to find
// the canonical weapon hash they map to. Each weapon entity in the binary has both
// a session-variable ID AND a fingerprint (initial mag capacity, weapon type) that
// matches a known canonical weapon.
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
		fmt.Fprintln(os.Stderr, "Usage: sesweapon <file.rec>")
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

	// For each unknown loadout slot (gameID with high byte != 0x37), find the weapon's
	// initial-capacity fingerprint and try to match to a canonical weapon.

	// Step 1: build per-player ammo summary keyed by Hash2 (which slot it is)
	type slot struct {
		hash2 uint32
		maxCap uint32
		shotCount int
		weaponRef uint32
	}
	perPlayer := make(map[int]map[uint32]*slot)
	for _, au := range r.AmmoUpdates {
		if au.PlayerIndex < 0 {
			continue
		}
		if perPlayer[au.PlayerIndex] == nil {
			perPlayer[au.PlayerIndex] = make(map[uint32]*slot)
		}
		s, ok := perPlayer[au.PlayerIndex][au.Hash2]
		if !ok {
			s = &slot{hash2: au.Hash2}
			perPlayer[au.PlayerIndex][au.Hash2] = s
		}
		if au.Capacity > s.maxCap {
			s.maxCap = au.Capacity
		}
		s.shotCount++
	}

	// Step 2: for each player, find their loadout secondaries from binary scan.
	// The loadout block has [gameID:8][auxHash:4][cat:4]. Look for slotMeleeWeapon
	// or slotSecondaryWeapon auxHashes.
	const (
		slotMelee   uint32 = 1696241262
		slotSecondaryWeapon uint32 = 1893246388
	)
	type loadEntry struct {
		offset int
		gameID uint64
		aux    uint32
	}
	var loadEntries []loadEntry
	scanLimit := 16384 // first 16KB has all loadout entries
	for off := 0; off+16 <= scanLimit && off+16 <= len(data); off++ {
		auxHash := binary.LittleEndian.Uint32(data[off+8 : off+12])
		if auxHash != slotMelee && auxHash != slotSecondaryWeapon {
			continue
		}
		gameID := binary.LittleEndian.Uint64(data[off : off+8])
		hi := (gameID >> 32) & 0xFF
		if gameID == 0 || (gameID>>40) != 0 || hi == 0 {
			continue
		}
		loadEntries = append(loadEntries, loadEntry{off, gameID, auxHash})
	}

	fmt.Println("=== Loadout secondary entries by offset ===")
	for _, le := range loadEntries {
		role := "secondary"
		if le.aux == slotMelee {
			role = "melee"
		}
		fmt.Printf("  off=%-7d  gameID=0x%X  slot=%s\n", le.offset, le.gameID, role)
	}
	fmt.Println()

	// Step 3: for each player, list their ammo-update profile sorted by capacity descending
	fmt.Println("=== Per-player ammo profile (Hash2 → maxCap, shotCount) ===")
	for pi := 0; pi < len(r.Header.Players); pi++ {
		p := r.Header.Players[pi]
		role := "Atk"
		if p.TeamIndex < len(r.Header.Teams) && r.Header.Teams[p.TeamIndex].Role == dissect.Defense {
			role = "Def"
		}
		fmt.Printf("  [%d] %s %s (%s):\n", pi, p.Username, role, p.Operator.String())
		slots := perPlayer[pi]
		if slots == nil {
			fmt.Println("    (no ammo updates)")
			continue
		}
		var keys []uint32
		for k := range slots {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return slots[keys[i]].maxCap > slots[keys[j]].maxCap })
		for _, k := range keys {
			s := slots[k]
			label := slotLabel(k)
			fmt.Printf("    Hash2=0x%08X (%-9s)  maxCap=%-3d  events=%d\n", k, label, s.maxCap, s.shotCount)
		}
	}

	// Step 4: WeaponID from kill events (0x65DD6CF8) — sample correlation
	fmt.Println()
	fmt.Println("=== Weapon-ID per kill (from 0x65DD6CF8) ===")
	weaponIDsByPlayer := map[string]map[uint64]int{}
	killSig := []byte{0x22, 0xD9, 0x13, 0x3C, 0xBA}
	for i := 0; i+5 < len(data); i++ {
		if !bytes.Equal(data[i:i+5], killSig) {
			continue
		}
		off := i + 5
		alen := int(data[off])
		off++
		if alen > 64 || off+alen > len(data) {
			continue
		}
		atk := string(data[off : off+alen])
		// Search for 0x65DD6CF8 in window
		var wid uint64
		start := i - 256
		if start < 0 {
			start = 0
		}
		end := i + 256
		if end+13 > len(data) {
			end = len(data) - 13
		}
		for j := start; j+9 < end; j++ {
			if data[j] != 0x22 && data[j] != 0x23 {
				continue
			}
			h := binary.LittleEndian.Uint32(data[j+1 : j+5])
			if h == 0x65DD6CF8 && data[j+5] == 0x08 && j+14 <= len(data) {
				wid = binary.LittleEndian.Uint64(data[j+6 : j+14])
				break
			}
		}
		if wid != 0 && atk != "" {
			if weaponIDsByPlayer[atk] == nil {
				weaponIDsByPlayer[atk] = map[uint64]int{}
			}
			weaponIDsByPlayer[atk][wid]++
		}
	}
	for player, ids := range weaponIDsByPlayer {
		fmt.Printf("  %s:\n", player)
		for wid, count := range ids {
			fmt.Printf("    weaponID=0x%X kills=%d\n", wid, count)
		}
	}
}

func slotLabel(h uint32) string {
	switch h {
	case 0x00000000:
		return "primary"
	case 0x29C80A40:
		return "secondary"
	case 0xAA4BBC34:
		return "grenade"
	case 0x653E26DD:
		return "op_gadget"
	}
	return "?"
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
