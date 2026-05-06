// opslot: find the auxHash slot identifier for operator-specific gadgets.
// Strategy: look for known gadget gameIDs in the binary and dump the auxHash
// that follows each one in the loadout block.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	"github.com/wnc-replay/replay-tool/dissect"
)

// Known signature gadget hashes from the data dump
var sigGadgets = map[uint64]string{
	0x4ACA9EC037: "SHOCK WIRE",
	0x5917D2F8F3: "SHOCK WIRE V2",
	0x37802D123D: "RTILA ELECTROCLAW",
	0x37802D1C97: "RTILA ELECTROCLAW V2",
	0x37802D1252: "WELCOME MAT",
	0x37802D1AAB: "WELCOME MAT V2",
	0x37802D1244: "SILENT STEP",
	0x37802D1938: "SILENT STEP V2",
	0x37802D1240: "SHOCK DRONE",
	0x37802D20F9: "SHOCK DRONE V2",
	0x37802D1243: "SIGNAL DISRUPTOR",
	0x37802D1E3A: "SIGNAL DISRUPTOR V2",
	0x37802D1226: "GLANCE SMART GLASSES",
	0x37802D21B4: "GLANCE SMART GLASSES V2",
	0x518A2BF339: "BANSHEE",
	0x533C4F01B6: "BANSHEE V2",
	0x56EC57FB3B: "KIBA BARRIER",
	0x56EC57FCA8: "KIBA BARRIER V2",
	0x483B8ECA63: "KS79 LIFELINE",
	0x483B8ECA96: "KS79 LIFELINE V2",
	0x37802D1209: "BREACHING HAMMER",
	0x37802D1FB7: "BREACHING HAMMER V2",
	0x3D4220A12D: "S.E.L.M.A.",
	0x3D4220A13A: "S.E.L.M.A. V2",
	0x483B8E5C02: "BREACHING ROUND",
	0x483B8E5C27: "BREACHING ROUND V2",
	0x5C9F2F26B7: "RAM BU-GI",
	0x5C9F2F26F0: "RAM BU-GI V2",
	0x483B8ECA10: "KULAKOV",
	0x483B8ECA4C: "KULAKOV V2",
	0x433FBE50DD: "ERC-7",
	0x433FBE5216: "ERC-7 V2",
	// Universal items at the slot we're investigating
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: opslot <file.rec>")
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer f.Close()
	r, err := dissect.NewReader(f)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	var buf bytes.Buffer
	r.Write(&buf)
	data := buf.Bytes()
	fmt.Printf("Decompressed: %d bytes\n\n", len(data))

	// For each known gadget hash, find ALL occurrences and the 4 bytes that follow (auxHash).
	auxHashCounts := make(map[uint32]int) // auxHash → count
	type hit struct {
		hash    uint64
		name    string
		offset  int
		aux     uint32
	}
	var hits []hit
	for hash, name := range sigGadgets {
		hashBytes := make([]byte, 8)
		binary.LittleEndian.PutUint64(hashBytes, hash)
		idx := 0
		for {
			pos := bytes.Index(data[idx:], hashBytes)
			if pos < 0 {
				break
			}
			absPos := idx + pos
			idx = absPos + 1
			// Read the 4 bytes after the gameID — that's the auxHash slot identifier
			if absPos+12 > len(data) {
				continue
			}
			aux := binary.LittleEndian.Uint32(data[absPos+8 : absPos+12])
			// Filter: aux must look like a real auxHash (high byte != 0, in known range)
			if aux == 0 {
				continue
			}
			auxHashCounts[aux]++
			hits = append(hits, hit{hash, name, absPos, aux})
		}
	}

	fmt.Println("=== auxHash distribution following known signature gadget hashes ===")
	fmt.Println("(Multiple hits per gadget = multiple replay events; we want the loadout-block auxHash)")
	type ahCount struct {
		aux   uint32
		count int
	}
	var ahs []ahCount
	for a, c := range auxHashCounts {
		ahs = append(ahs, ahCount{a, c})
	}
	for _, ah := range ahs {
		fmt.Printf("  auxHash=0x%08X (decimal=%d) count=%d\n", ah.aux, ah.aux, ah.count)
	}
	fmt.Println()

	fmt.Println("=== First 25 hits with their auxHashes ===")
	for i, h := range hits {
		if i >= 25 {
			break
		}
		fmt.Printf("  off=%-10d hash=0x%X (%-22s) aux=0x%08X\n", h.offset, h.hash, h.name, h.aux)
	}
}
