// ammoref: dump every player's weapon entity refs along with the property hashes
// (Hash1/Hash2) reported in their ammo updates. These hashes are the actual binary
// weapon identifiers — fully deterministic, not session-variable for *gun behavior*.
package main

import (
	"bytes"
	"fmt"
	"os"
	"sort"

	"github.com/wnc-replay/replay-tool/dissect"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: ammoref <file.rec>")
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	must(err)
	defer f.Close()
	r, err := dissect.NewReader(f)
	must(err)
	var buf bytes.Buffer
	r.Write(&buf)
	r.Read()

	type slotKey struct {
		playerIdx int
		hash1     uint32
		hash2     uint32
	}
	type slotInfo struct {
		count        int
		minAvailable uint32
		maxCapacity  uint32
		minOff       int
	}
	slots := make(map[slotKey]*slotInfo)

	for _, au := range r.AmmoUpdates {
		if au.PlayerIndex < 0 {
			continue
		}
		k := slotKey{au.PlayerIndex, au.Hash1, au.Hash2}
		s, ok := slots[k]
		if !ok {
			s = &slotInfo{minAvailable: au.Available, maxCapacity: au.Capacity, minOff: au.BinOffset}
			slots[k] = s
		}
		s.count++
		if au.Available < s.minAvailable {
			s.minAvailable = au.Available
		}
		if au.Capacity > s.maxCapacity {
			s.maxCapacity = au.Capacity
		}
		if au.BinOffset < s.minOff {
			s.minOff = au.BinOffset
		}
	}

	type row struct {
		k slotKey
		s *slotInfo
	}
	var rows []row
	for k, s := range slots {
		rows = append(rows, row{k, s})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].k.playerIdx != rows[j].k.playerIdx {
			return rows[i].k.playerIdx < rows[j].k.playerIdx
		}
		return rows[i].s.count > rows[j].s.count
	})

	fmt.Println("Per-player ammo-update slots (each unique Hash1+Hash2 is a weapon/gadget instance)")
	fmt.Println("Hash1 = player/property hash, Hash2 = gear/weapon hash")
	fmt.Println()
	for _, row := range rows {
		username := "?"
		op := "?"
		if row.k.playerIdx >= 0 && row.k.playerIdx < len(r.Header.Players) {
			username = r.Header.Players[row.k.playerIdx].Username
			op = r.Header.Players[row.k.playerIdx].Operator.String()
		}
		role := "Atk"
		if row.k.playerIdx < len(r.Header.Players) && row.k.playerIdx < len(r.Header.Teams) {
			ti := r.Header.Players[row.k.playerIdx].TeamIndex
			if ti < len(r.Header.Teams) && r.Header.Teams[ti].Role == dissect.Defense {
				role = "Def"
			}
		}
		fmt.Printf("  [%d] %-22s %s %-12s hash1=0x%08X hash2=0x%08X count=%-4d cap=%-3d minOff=%d\n",
			row.k.playerIdx, username, role, op,
			row.k.hash1, row.k.hash2, row.s.count, row.s.maxCapacity, row.s.minOff)
	}
}

func must(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
