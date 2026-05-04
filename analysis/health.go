package analysis

import (
	"encoding/binary"
	"math"
)

const healthHash = 0x4171D3C3 // health property hash

// ExtractHealthUpdates scans the post-80% region of the binary for health
// property updates (hash 0x4171D3C3) and maps them to players.
func ExtractHealthUpdates(data []byte, entityToPlayer map[uint32]int, ticks []TimerTick) []HealthUpdate {
	if len(data) < 100 {
		return nil
	}

	// Scan post-80% region where health updates are concentrated
	startOff := len(data) / 100 * 80
	var updates []HealthUpdate
	hashBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(hashBytes, healthHash)

	for i := startOff; i+16 <= len(data); i++ {
		if data[i] != hashBytes[0] || data[i+1] != hashBytes[1] ||
			data[i+2] != hashBytes[2] || data[i+3] != hashBytes[3] {
			continue
		}

		// Health value (float32) follows the hash
		if i+8 > len(data) {
			continue
		}
		hpBits := binary.LittleEndian.Uint32(data[i+4 : i+8])
		hp := math.Float32frombits(hpBits)

		// Validate: health should be 0-125 (some operators have extra HP)
		if hp < 0 || hp > 130 || math.IsNaN(float64(hp)) || math.IsInf(float64(hp), 0) {
			continue
		}

		// Find owning entity: scan ±128 bytes for F0-prefix entity ref
		entityRef := findNearbyEntity(data, i, 128)
		if entityRef == 0 {
			continue
		}

		pIdx, ok := entityToPlayer[entityRef]
		if !ok {
			pIdx = -1
		}

		updates = append(updates, HealthUpdate{
			PlayerIndex: pIdx,
			Health:      hp,
			BinOffset:   i,
		})
	}

	return updates
}

// findNearbyEntity scans ±radius bytes from offset for an F0-prefix entity ref.
func findNearbyEntity(data []byte, offset, radius int) uint32 {
	start := offset - radius
	if start < 0 {
		start = 0
	}
	end := offset + radius
	if end+4 > len(data) {
		end = len(data) - 4
	}

	bestRef := uint32(0)
	bestDist := radius + 1

	for j := start; j <= end; j++ {
		ref := binary.LittleEndian.Uint32(data[j : j+4])
		if ref>>24 >= 0xF0 {
			d := j - offset
			if d < 0 {
				d = -d
			}
			if d < bestDist {
				bestDist = d
				bestRef = ref
			}
		}
	}

	return bestRef
}
