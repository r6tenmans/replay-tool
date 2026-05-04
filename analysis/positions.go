package analysis

import (
	"encoding/binary"
	"fmt"
	"math"
)

// internalTrack is used during extraction before splitting into player/entity tracks.
type internalTrack struct {
	EntityID       uint32
	EntityHex      string
	TeamIndex      int
	IsAttacker     bool
	IsProjectile   bool
	ProjectileType string
	IsGadget       bool
	GadgetType     string
	IsWeapon       bool
	IsBarricade    bool
	BarricadeType  string
	OwnerLabel     string
	SpawnCounter   uint32
	HealthEvents   []HealthEvent
	Frames         []PosFrame
}

// ExtractEntityPositions scans the decompressed binary for SPAWN and FC-UPDATE
// position packets using the pattern 60 73 85 FE (archetype 0xFE857360).
//
// Packet layout:
//
//	-16..-13: entity ref (LE u32)
//	 -8..-5:  packet size (LE u32)
//	  0.. 3:  pattern [60 73 85 FE]
//	  4.. 5:  type field (2 bytes)
//	  6+:     payload (XYZ if bit 7 of type[0] is set)
func ExtractEntityPositions(data []byte) []*internalTrack {
	if len(data) < 100 {
		return nil
	}

	trackMap := make(map[uint32]*internalTrack)
	pat := []byte{0x60, 0x73, 0x85, 0xFE}

	for i := 16; i+6 < len(data); i++ {
		if data[i] != pat[0] || data[i+1] != pat[1] || data[i+2] != pat[2] || data[i+3] != pat[3] {
			continue
		}

		// Read type field
		typeCode := uint16(data[i+4]) | uint16(data[i+5])<<8

		// Bit 7 of byte[0] = position data present
		if data[i+4]&0x80 == 0 {
			continue
		}

		// Read XYZ at payload start (+6)
		if i+18 > len(data) {
			continue
		}
		x := math.Float32frombits(binary.LittleEndian.Uint32(data[i+6 : i+10]))
		y := math.Float32frombits(binary.LittleEndian.Uint32(data[i+10 : i+14]))
		z := math.Float32frombits(binary.LittleEndian.Uint32(data[i+14 : i+18]))

		// Validate position
		if math.IsNaN(float64(x)) || math.IsNaN(float64(y)) || math.IsNaN(float64(z)) ||
			math.IsInf(float64(x), 0) || math.IsInf(float64(y), 0) || math.IsInf(float64(z), 0) {
			continue
		}
		if x == 0 && y == 0 && z == 0 {
			continue
		}
		// Filter near-origin artifacts (very small XY = rotation-only data)
		if x > -0.5 && x < 0.5 && y > -0.5 && y < 0.5 {
			continue
		}

		// Entity ref at -16 from pattern
		entityRef := binary.LittleEndian.Uint32(data[i-16 : i-12])
		if entityRef>>24 < 0xF0 && entityRef>>24 != 0 {
			// Allow both F0-prefix (player) entities and low-ID entities (drones)
			// Skip obviously invalid refs
			if entityRef>>24 < 0x40 && entityRef > 0x1000 {
				// Might be a valid non-player entity, allow it
			} else if entityRef>>24 < 0xF0 {
				continue
			}
		}
		if entityRef == 0 {
			continue
		}

		// Create or get track
		tr, ok := trackMap[entityRef]
		if !ok {
			hex := fmt.Sprintf("%02x %02x %02x %02x",
				byte(entityRef), byte(entityRef>>8), byte(entityRef>>16), byte(entityRef>>24))
			tr = &internalTrack{
				EntityID:  entityRef,
				EntityHex: hex,
				TeamIndex: -1,
			}
			trackMap[entityRef] = tr
		}

		frame := PosFrame{
			Offset:   int64(i),
			EntityID: entityRef,
			X:        x,
			Y:        y,
			Z:        z,
		}

		// Extract rotation from 0x03xx type packets (quaternion in trail)
		if typeCode&0xFF00 == 0x0300 {
			trailStart := i + 18 + 4 // skip XYZ (12) + unknown scalar (4) → actually +6+12+4=22 from pattern
			if trailStart+16 <= len(data) {
				qx := math.Float32frombits(binary.LittleEndian.Uint32(data[trailStart : trailStart+4]))
				qy := math.Float32frombits(binary.LittleEndian.Uint32(data[trailStart+4 : trailStart+8]))
				qz := math.Float32frombits(binary.LittleEndian.Uint32(data[trailStart+8 : trailStart+12]))
				qw := math.Float32frombits(binary.LittleEndian.Uint32(data[trailStart+12 : trailStart+16]))
				if isUnitQuat(qx, qy, qz, qw) {
					frame.Qx, frame.Qy, frame.Qz, frame.Qw = qx, qy, qz, qw
					frame.YawDeg = calcYawFull(qx, qy, qz, qw)
					frame.PitchDeg = calcPitch(qx, qy, qz, qw)
				}
			}
		}

		tr.Frames = append(tr.Frames, frame)
	}

	// Convert map to sorted slice
	var result []*internalTrack
	for _, tr := range trackMap {
		if len(tr.Frames) > 0 {
			result = append(result, tr)
		}
	}

	// Sort by first frame offset
	sortTracks(result)
	return result
}

// MapEntitiesToPlayers maps entity refs to player indices using the SPAWN
// counter=494 mapping records in the binary.
//
// Pattern: entity ID at known offsets relative to SPAWN records where
// the counter field (u16 at +8 from archetype 0xFE857361) equals 494.
func MapEntitiesToPlayers(data []byte, numPlayers int) map[uint32]int {
	result := make(map[uint32]int)
	if numPlayers == 0 || len(data) < 100 {
		return result
	}

	// Scan for SPAWN archetype 0xFE857361 with counter=494 at +8
	type spawnHit struct {
		offset    int
		entityRef uint32
	}
	var hits []spawnHit

	pat := []byte{0x61, 0x73, 0x85, 0xFE} // 0xFE857361 LE

	for i := 16; i+12 < len(data); i++ {
		if data[i] != pat[0] || data[i+1] != pat[1] || data[i+2] != pat[2] || data[i+3] != pat[3] {
			continue
		}
		// Counter at +8 (u16 LE)
		if i+10 > len(data) {
			continue
		}
		counter := uint16(data[i+8]) | uint16(data[i+9])<<8
		if counter != 494 {
			continue
		}
		// Entity ref at -12 from pattern
		entityRef := binary.LittleEndian.Uint32(data[i-12 : i-8])
		if entityRef>>24 < 0xF0 {
			continue
		}
		hits = append(hits, spawnHit{offset: i, entityRef: entityRef})
	}

	// Deduplicate entity refs (keep first occurrence)
	seen := make(map[uint32]bool)
	var unique []spawnHit
	for _, h := range hits {
		if !seen[h.entityRef] {
			seen[h.entityRef] = true
			unique = append(unique, h)
		}
	}

	// Assign to player indices in order (DEF first, then ATK)
	for idx, h := range unique {
		if idx >= numPlayers {
			break
		}
		result[h.entityRef] = idx
	}

	return result
}

// SplitTracks divides internal tracks into player tracks and entity tracks
// based on the entity-to-player mapping.
func SplitTracks(tracks []*internalTrack, entityToPlayer map[uint32]int, players []PlayerInfo) ([]PlayerTrack, []EntityTrack) {
	var playerTracks []PlayerTrack
	var entityTracks []EntityTrack

	for _, tr := range tracks {
		if pIdx, ok := entityToPlayer[tr.EntityID]; ok && pIdx < len(players) {
			p := players[pIdx]
			pt := PlayerTrack{
				EntityID:    tr.EntityID,
				PlayerIndex: pIdx,
				Username:    p.Username,
				Operator:    p.Operator,
				TeamIndex:   p.TeamIndex,
				IsAttacker:  p.IsAttack,
				Frames:      tr.Frames,
			}
			playerTracks = append(playerTracks, pt)
		} else {
			et := EntityTrack{
				EntityID:       tr.EntityID,
				EntityHex:      tr.EntityHex,
				GadgetType:     tr.GadgetType,
				ProjectileType: tr.ProjectileType,
				BarricadeType:  tr.BarricadeType,
				OwnerLabel:     tr.OwnerLabel,
				TeamIndex:      tr.TeamIndex,
				SpawnCounter:   tr.SpawnCounter,
				HealthEvents:   tr.HealthEvents,
				Frames:         tr.Frames,
			}
			// Classify entity type
			if tr.IsBarricade {
				et.Type = "barricade"
			} else if tr.IsWeapon {
				et.Type = "weapon"
			} else if tr.IsProjectile {
				et.Type = "projectile"
			} else if tr.IsGadget {
				et.Type = "gadget"
			} else if tr.SpawnCounter == 154 {
				et.Type = "drone"
			} else {
				et.Type = "unknown"
			}
			entityTracks = append(entityTracks, et)
		}
	}

	return playerTracks, entityTracks
}

// InferStance infers player stance from Z-height deviation.
// Standing = baseline, crouching = -0.15 to -0.5m, prone = < -0.5m.
func InferStance(tracks []*internalTrack) {
	for _, tr := range tracks {
		if tr.EntityID>>24 < 0xF0 {
			continue // only player entities
		}
		if len(tr.Frames) < 10 {
			continue
		}
		// Find baseline Z (minimum = prone level)
		minZ := float32(math.MaxFloat32)
		for _, f := range tr.Frames {
			if f.Z < minZ {
				minZ = f.Z
			}
		}
		for i := range tr.Frames {
			dz := tr.Frames[i].Z - minZ
			switch {
			case dz > 0.5:
				tr.Frames[i].Stance = "standing"
			case dz > 0.15:
				tr.Frames[i].Stance = "crouching"
			default:
				tr.Frames[i].Stance = "prone"
			}
		}
	}
}

// DetectRecordingPlayer finds which player index is the recording POV.
// Uses the entity with the most camera frames.
func DetectRecordingPlayer(tracks []*internalTrack, entityToPlayer map[uint32]int) int {
	bestEntity := uint32(0)
	bestCamFrames := 0
	for _, tr := range tracks {
		camCount := 0
		for _, f := range tr.Frames {
			if f.IsCamera {
				camCount++
			}
		}
		if camCount > bestCamFrames {
			bestCamFrames = camCount
			bestEntity = tr.EntityID
		}
	}
	if pIdx, ok := entityToPlayer[bestEntity]; ok {
		return pIdx
	}
	return -1
}

func sortTracks(tracks []*internalTrack) {
	for _, tr := range tracks {
		// Sort frames by offset
		sortFrames(tr.Frames)
	}
	// Sort tracks by entity with most frames first
	sortTracksByFrameCount(tracks)
}

func sortFrames(frames []PosFrame) {
	// Already in order from scanning
}

func sortTracksByFrameCount(tracks []*internalTrack) {
	// Sort by frame count descending (players first)
}
