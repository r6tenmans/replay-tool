// bonediscover: catalog every "bone payload" shape in the binary. The payload
// is the distinctive 36-byte block: [xyz f32 x3][1.0 sep][quat 4×f32][1.0 sep],
// where the XYZ is bounded (<2m) and the quat is unit-length. For each match,
// capture the bytes BEFORE the payload as candidate magics. Common magics that
// aren't BMA/BMB indicate additional bones we don't yet decode.
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"sort"

	"github.com/wnc-replay/replay-tool/dissect"
)

const magicLen = 6 // capture 6 bytes before each candidate payload

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: bonediscover <file.rec>")
		os.Exit(1)
	}
	f, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer f.Close()
	r, err := dissect.NewReader(f)
	if err != nil {
		panic(err)
	}
	var buf bytes.Buffer
	r.Write(&buf)
	data := buf.Bytes()

	// Walk every offset. A "bone payload" is 36 bytes starting at payloadOff:
	//   [0..12]   = XYZ f32 (each |v| < 2)
	//   [12..16]  = 1.0 sep
	//   [16..32]  = quat f32 x4 (unit-length)
	//   [32..36]  = 1.0 sep
	//
	// For each match, the candidate magic is bytes [payloadOff-magicLen .. payloadOff].

	magicCount := make(map[[magicLen]byte]int)
	magicFirstOff := make(map[[magicLen]byte]int)

	for payloadOff := magicLen; payloadOff+36 <= len(data); payloadOff++ {
		// Quick reject: separators must be ~1.0
		sep1Bits := binary.LittleEndian.Uint32(data[payloadOff+12 : payloadOff+16])
		sep2Bits := binary.LittleEndian.Uint32(data[payloadOff+32 : payloadOff+36])
		sep1 := math.Float32frombits(sep1Bits)
		sep2 := math.Float32frombits(sep2Bits)
		if sep1 < 0.99 || sep1 > 1.01 || sep2 < 0.99 || sep2 > 1.01 {
			continue
		}
		// XYZ bounds
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12]))
		if !inBound(x) || !inBound(y) || !inBound(z) {
			continue
		}
		// Quat unit-length
		qx := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+16 : payloadOff+20]))
		qy := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+20 : payloadOff+24]))
		qz := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+24 : payloadOff+28]))
		qw := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+28 : payloadOff+32]))
		mag := float64(qx)*float64(qx) + float64(qy)*float64(qy) + float64(qz)*float64(qz) + float64(qw)*float64(qw)
		if mag < 0.8 || mag > 1.2 {
			continue
		}

		var magic [magicLen]byte
		copy(magic[:], data[payloadOff-magicLen:payloadOff])
		magicCount[magic]++
		if _, exists := magicFirstOff[magic]; !exists {
			magicFirstOff[magic] = payloadOff
		}
	}

	// Sort magics by count desc
	type magicStat struct {
		magic    [magicLen]byte
		count    int
		firstOff int
	}
	var stats []magicStat
	for m, c := range magicCount {
		stats = append(stats, magicStat{m, c, magicFirstOff[m]})
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].count > stats[j].count })

	// Known magics
	bma := []byte{0x02, 0x00, 0x70, 0x88, 0x98, 0x58}
	bmbPad := []byte{0x00, 0x00, 0x2C, 0x36, 0x14, 0x9B} // 5-byte BMB padded to 6

	fmt.Printf("Found %d unique candidate magics with bone-shaped payloads.\n", len(stats))
	fmt.Println("Top 30 by frequency:")
	fmt.Println("(magics with count > 100 are likely real bone signatures)")
	fmt.Println()
	for i, s := range stats {
		if i >= 30 || s.count < 50 {
			break
		}
		label := ""
		if bytes.Equal(s.magic[:], bma) {
			label = " [BMA — head]"
		} else if bytes.Equal(s.magic[:6], bmbPad[:6]) || (s.magic[1] == 0x00 && s.magic[2] == 0x2C && s.magic[3] == 0x36 && s.magic[4] == 0x14 && s.magic[5] == 0x9B) {
			label = " [BMB — chest]"
		}
		fmt.Printf("  %02X %02X %02X %02X %02X %02X  count=%-6d firstOff=%d%s\n",
			s.magic[0], s.magic[1], s.magic[2], s.magic[3], s.magic[4], s.magic[5],
			s.count, s.firstOff, label)
	}

	// Also show 5-byte trailing patterns (last 5 bytes of magic) — useful for BMB
	// which has a 5-byte magic embedded in our 6-byte capture.
	fmt.Println()
	fmt.Println("Top 30 by last-5-byte suffix (catches 5-byte magics within 6-byte window):")
	suffix5Count := make(map[[5]byte]int)
	suffix5FirstOff := make(map[[5]byte]int)
	for m, c := range magicCount {
		var s5 [5]byte
		copy(s5[:], m[1:])
		suffix5Count[s5] += c
		if _, ok := suffix5FirstOff[s5]; !ok {
			suffix5FirstOff[s5] = magicFirstOff[m]
		}
	}
	type s5Stat struct {
		s5    [5]byte
		count int
		off   int
	}
	var s5Stats []s5Stat
	for s, c := range suffix5Count {
		s5Stats = append(s5Stats, s5Stat{s, c, suffix5FirstOff[s]})
	}
	sort.Slice(s5Stats, func(i, j int) bool { return s5Stats[i].count > s5Stats[j].count })
	for i, s := range s5Stats {
		if i >= 30 || s.count < 100 {
			break
		}
		fmt.Printf("  %02X %02X %02X %02X %02X  count=%-6d firstOff=%d\n",
			s.s5[0], s.s5[1], s.s5[2], s.s5[3], s.s5[4], s.count, s.off)
	}
}

func inBound(v float32) bool {
	if v < 0 {
		v = -v
	}
	return v < 2.0 && v != 0 // strict: exclude exact-zero (probably padding)
}
