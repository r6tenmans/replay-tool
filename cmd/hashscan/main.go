// hashscan: scan multiple .rec files for the same gadget hashes to cross-reference operators.
// Usage: hashscan <hash_hex> <file1.rec> [file2.rec ...]
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	"github.com/wnc-replay/replay-tool/dissect"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: hashscan <hash_hex_uint64> <file1.rec> [file2.rec ...]")
		os.Exit(1)
	}
	hash, err := strconv.ParseUint(os.Args[1], 0, 64)
	if err != nil {
		fmt.Fprintln(os.Stderr, "bad hash:", err)
		os.Exit(1)
	}
	hashBytes := make([]byte, 8)
	binary.LittleEndian.PutUint64(hashBytes, hash)

	for _, path := range os.Args[2:] {
		f, err := os.Open(path)
		if err != nil {
			fmt.Printf("[skip] %s: %v\n", path, err)
			continue
		}
		r, err := dissect.NewReader(f)
		if err != nil {
			fmt.Printf("[skip] %s: %v\n", path, err)
			f.Close()
			continue
		}
		var buf bytes.Buffer
		r.Write(&buf)
		data := buf.Bytes()
		r.Read()
		f.Close()

		// Find first occurrence in early loadout block (< 12KB)
		hits := 0
		firstOff := -1
		for i := 0; i+8 <= len(data); i++ {
			match := true
			for j := 0; j < 8; j++ {
				if data[i+j] != hashBytes[j] {
					match = false
					break
				}
			}
			if match {
				if firstOff < 0 {
					firstOff = i
				}
				hits++
			}
		}

		if hits == 0 {
			fmt.Printf("[no-hit] %s\n", shortName(path))
			continue
		}

		// If first hit is in loadout block, deduce which player by 506-byte block index.
		// Defender block 0 starts ~off=7867 (Kaid pg at 8373 - 506 = 7867).
		operator := ""
		spawn := ""
		playerIdx := -1
		if firstOff > 0 && firstOff < 14000 {
			// Estimate player index from offset
			const blockSize = 506
			const block0Start = 7867
			if firstOff >= block0Start {
				playerIdx = (firstOff - block0Start) / blockSize
			}
			if playerIdx >= 0 && playerIdx < len(r.Header.Players) {
				operator = r.Header.Players[playerIdx].Operator.String()
				spawn = r.Header.Players[playerIdx].Spawn
			}
		}
		fmt.Printf("%-50s firstOff=%-8d hits=%-3d player[%d]=%s (%s)\n",
			shortName(path), firstOff, hits, playerIdx, operator, spawn)
	}
}

func shortName(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '\\' || p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}
