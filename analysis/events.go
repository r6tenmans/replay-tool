package analysis

import (
	"bytes"
	"encoding/binary"
)

// ExtractBinaryFeedback parses kill/death/DBNO events directly from the binary.
// Kill signature: 22 D9 13 3C BA
// DBNO signature: 22 96 E2 29 7F (within ±70 bytes of kill)
func ExtractBinaryFeedback(data []byte) []BinaryMatchEvent {
	killSig := []byte{0x22, 0xD9, 0x13, 0x3C, 0xBA}
	dbnoSig := []byte{0x22, 0x96, 0xE2, 0x29, 0x7F}

	type eventKey struct {
		typ, attacker, target string
	}
	seen := make(map[eventKey]bool)
	var events []BinaryMatchEvent

	for i := 0; i+5 < len(data); i++ {
		if data[i] != 0x22 || !bytes.Equal(data[i:i+5], killSig) {
			continue
		}

		off := i + 5

		// Attacker username: 1-byte length + string
		if off >= len(data) {
			continue
		}
		attackerLen := int(data[off])
		off++
		if attackerLen > 64 || off+attackerLen > len(data) {
			continue
		}
		attacker := string(data[off : off+attackerLen])
		off += attackerLen

		// Skip 15 bytes
		off += 15
		if off >= len(data) {
			continue
		}

		// Target username: 1-byte length + string
		targetLen := int(data[off])
		off++
		if targetLen > 64 || off+targetLen > len(data) {
			continue
		}
		target := string(data[off : off+targetLen])
		off += targetLen

		// Skip 56 bytes to headshot field
		off += 56
		if off >= len(data) {
			continue
		}
		headshot := data[off] == 1

		// Validate
		if len(target) == 0 || !isPrintableASCII(target) {
			continue
		}
		if len(attacker) > 0 && !isPrintableASCII(attacker) {
			continue
		}

		// Check for DBNO marker within ±70 bytes
		isDBNO := false
		searchStart := i - 70
		if searchStart < 0 {
			searchStart = 0
		}
		searchEnd := i + 70
		if searchEnd+5 > len(data) {
			searchEnd = len(data) - 5
		}
		for j := searchStart; j <= searchEnd; j++ {
			if data[j] == 0x22 && bytes.Equal(data[j:j+5], dbnoSig) {
				isDBNO = true
				break
			}
		}

		evType := "kill"
		if len(attacker) == 0 {
			evType = "death"
		}

		key := eventKey{evType, attacker, target}
		if seen[key] {
			continue
		}
		seen[key] = true

		events = append(events, BinaryMatchEvent{
			Offset:   int64(i),
			Type:     evType,
			Attacker: attacker,
			Target:   target,
			Headshot: headshot,
		})

		// Emit separate DBNO event
		if isDBNO {
			dbnoKey := eventKey{"dbno", attacker, target}
			if !seen[dbnoKey] {
				seen[dbnoKey] = true
				events = append(events, BinaryMatchEvent{
					Offset:   int64(i),
					Type:     "dbno",
					Attacker: attacker,
					Target:   target,
					Headshot: headshot,
				})
			}
		}
	}

	return events
}

// ExtractGameActions scans for reinforce and gadget deploy binary patterns.
func ExtractGameActions(data []byte, ticks []TimerTick) []GameAction {
	reinforcePat := []byte{0x46, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x35}
	gadgetPat := []byte{0x50, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x3F}

	totalDuration := RoundDurationFromTicks(ticks)
	var actions []GameAction

	for i := 0; i+10 <= len(data); i++ {
		var actionType string
		if bytes.Equal(data[i:i+10], reinforcePat) {
			actionType = "reinforce"
		} else if bytes.Equal(data[i:i+10], gadgetPat) {
			actionType = "gadget_deploy"
		}
		if actionType == "" {
			continue
		}

		// Estimate time from binary offset fraction
		timeSecs := float64(0)
		if totalDuration > 0 {
			frac := float64(i) / float64(len(data))
			timeSecs = frac * float64(totalDuration)
		}

		// Dedup: skip if within 3 seconds of previous same-type action
		dup := false
		for _, prev := range actions {
			if prev.Type == actionType {
				dt := timeSecs - prev.TimeSecs
				if dt < 0 {
					dt = -dt
				}
				if dt < 3 {
					dup = true
					break
				}
			}
		}
		if dup {
			continue
		}

		actions = append(actions, GameAction{
			Type:     actionType,
			TimeSecs: timeSecs,
			Offset:   i,
		})
	}

	return actions
}

// ExtractSpawnCounters reads entity SPAWN counter values.
// Pattern: archetype 0xFE857361, counter u16 at +8.
func ExtractSpawnCounters(data []byte) map[uint32]uint32 {
	result := make(map[uint32]uint32)
	pat := []byte{0x61, 0x73, 0x85, 0xFE}

	for i := 16; i+10 < len(data); i++ {
		if data[i] != pat[0] || data[i+1] != pat[1] || data[i+2] != pat[2] || data[i+3] != pat[3] {
			continue
		}
		entityRef := binary.LittleEndian.Uint32(data[i-12 : i-8])
		counter := uint16(data[i+8]) | uint16(data[i+9])<<8
		if _, exists := result[entityRef]; !exists {
			result[entityRef] = uint32(counter)
		}
	}

	return result
}

// ClassifyEntities classifies non-player entities based on SPAWN counters
// and FC-UPDATE flags.
func ClassifyEntities(tracks []*internalTrack, counters map[uint32]uint32,
	data []byte, players []PlayerInfo) {

	for _, tr := range tracks {
		counter, hasCounter := counters[tr.EntityID]
		tr.SpawnCounter = counter

		if !hasCounter {
			continue
		}

		switch counter {
		case 154: // drone
			// Will be classified as "drone" in SplitTracks
		case 146: // gadget
			tr.IsGadget = true
		case 130: // barricade
			tr.IsBarricade = true
			tr.BarricadeType = "barricade"
		case 138, 254: // weapon
			tr.IsWeapon = true
		}
	}
}

// ExtractLoadouts scans binary header for equipment loadout records.
// Uses auxHash slot identifiers to classify items into loadout slots.
// Each record: [GameID u64] [auxHash u32] [category u32] (16 bytes)
func ExtractLoadouts(data []byte, players []PlayerInfo) []PlayerLoadout {
	if len(data) < 192 {
		return nil
	}

	const (
		catWep  = 0x0A
		catGadg = 0x03

		// CRC32 hashes of slot names
		slotPrimaryWeapon   uint32 = 3268402276 // "PrimaryWeapon"
		slotMeleeWeapon     uint32 = 1696241262 // "MeleeWeapon"
		slotReinforcement   uint32 = 2606078005 // "Reinforcement"
		slotSecondaryWeapon uint32 = 1893246388 // "SecondaryWeapon"
		slotSecondaryGadget uint32 = 2947831256 // "SecondaryGadget"
	)

	scanLimit := len(data) / 4
	if scanLimit < 1024 {
		scanLimit = len(data)
	}

	// Scan for all records with known slot auxHash values
	type slotRecord struct {
		offset  int
		gameID  uint64
		auxHash uint32
		cat     uint32
	}
	var records []slotRecord

	for off := 0; off+16 <= scanLimit; off++ {
		auxHash := binary.LittleEndian.Uint32(data[off+8 : off+12])

		// Filter to known slot hashes
		switch auxHash {
		case slotPrimaryWeapon, slotMeleeWeapon, slotReinforcement, slotSecondaryWeapon, slotSecondaryGadget:
			// Valid slot hash
		default:
			continue
		}

		gameID := binary.LittleEndian.Uint64(data[off : off+8])
		cat := binary.LittleEndian.Uint32(data[off+12 : off+16])

		// Validate game ID format
		hiByte := (gameID >> 32) & 0xFF
		upper3 := gameID >> 40
		if gameID == 0 || upper3 != 0 || hiByte == 0 {
			continue
		}

		// Category must be weapon (10) or gadget (3)
		if cat != catWep && cat != catGadg {
			continue
		}

		records = append(records, slotRecord{off, gameID, auxHash, cat})
	}

	if len(records) == 0 {
		return nil
	}

	// Group records into loadout blocks by proximity
	// Gaps: ~48 between slots in group, ~192 between weapon/gadget groups, ~202+ between players
	// Use 195 to include weapon+gadget groups but split between players
	const blockGap = 195
	var blocks [][]slotRecord
	var currentBlock []slotRecord

	for i, rec := range records {
		if i == 0 {
			currentBlock = append(currentBlock, rec)
			continue
		}

		// Check if this record is near the previous one
		prevOff := records[i-1].offset
		if rec.offset-prevOff <= blockGap {
			currentBlock = append(currentBlock, rec)
		} else {
			// Start new block
			if len(currentBlock) > 0 {
				blocks = append(blocks, currentBlock)
			}
			currentBlock = []slotRecord{rec}
		}
	}
	if len(currentBlock) > 0 {
		blocks = append(blocks, currentBlock)
	}

	// Build loadouts from blocks
	var loadouts []PlayerLoadout
	for idx, block := range blocks {
		if len(block) < 2 {
			continue // Need at least 2 items for a valid loadout
		}

		pl := PlayerLoadout{
			PlayerIndex: idx,
		}

		for _, rec := range block {
			item := LoadoutItem{
				GameID:   rec.gameID,
				AuxHash:  rec.auxHash,
				Name:     resolveItemName(rec.gameID),
				Category: int(rec.cat),
			}

			switch rec.auxHash {
			case slotPrimaryWeapon:
				if pl.PrimaryWeapon.GameID == 0 {
					pl.PrimaryWeapon = item
				}
			case slotMeleeWeapon:
				if pl.SecondaryWeapon.GameID == 0 {
					pl.SecondaryWeapon = item
				}
			case slotReinforcement:
				if pl.PrimaryGadget.GameID == 0 {
					pl.PrimaryGadget = item
				}
			case slotSecondaryWeapon:
				if pl.SecondaryWeapon.GameID == 0 {
					pl.SecondaryWeapon = item
				}
			case slotSecondaryGadget:
				if pl.SecondaryGadget.GameID == 0 {
					pl.SecondaryGadget = item
				}
			}
		}

		loadouts = append(loadouts, pl)
	}

	// Match loadouts to players (blocks appear in header player order)
	for i := range loadouts {
		if i < len(players) {
			loadouts[i].PlayerIndex = i
		}
	}

	return loadouts
}
