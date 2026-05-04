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
// Each record: [GameID u64] [auxHash u32] [category u32] (16 bytes)
// Categories: 0x16/0x18=operator, 0x0A=weapon, 0x03=gadget
func ExtractLoadouts(data []byte, players []PlayerInfo) []PlayerLoadout {
	if len(data) < 192 {
		return nil
	}

	const (
		catOp16 = 0x16
		catOp18 = 0x18
		catWep  = 0x0A
		catGadg = 0x03
	)

	type loadoutHit struct {
		offset int
		opID   uint64
	}

	var hits []loadoutHit
	scanLimit := len(data) / 4
	if scanLimit < 1024 {
		scanLimit = len(data)
	}

	for off := 0; off+16 <= scanLimit; off++ {
		gameID := binary.LittleEndian.Uint64(data[off : off+8])
		auxHash := binary.LittleEndian.Uint32(data[off+8 : off+12])
		cat := binary.LittleEndian.Uint32(data[off+12 : off+16])

		hiByte := (gameID >> 32) & 0xFF
		upper3 := gameID >> 40
		if upper3 != 0 || hiByte == 0 || auxHash != 0 {
			continue
		}
		if cat != catOp16 && cat != catOp18 {
			continue
		}
		if gameID < 0x100000000 {
			continue
		}

		hits = append(hits, loadoutHit{offset: off, opID: gameID})
	}

	var loadouts []PlayerLoadout
	for idx, h := range hits {
		pl := PlayerLoadout{
			PlayerIndex:  idx,
			OperatorID:   h.opID,
			OperatorName: resolveItemName(h.opID),
		}

		var weapons, gadgets []LoadoutItem

		for rec := 1; rec <= 11; rec++ {
			recOff := h.offset + rec*16
			if recOff+16 > len(data) {
				break
			}
			gameID := binary.LittleEndian.Uint64(data[recOff : recOff+8])
			auxHash := binary.LittleEndian.Uint32(data[recOff+8 : recOff+12])
			cat := binary.LittleEndian.Uint32(data[recOff+12 : recOff+16])

			hiByte := (gameID >> 32) & 0xFF
			upper3 := gameID >> 40
			if gameID == 0 || upper3 != 0 || hiByte == 0 {
				continue
			}

			item := LoadoutItem{
				GameID:   gameID,
				AuxHash:  auxHash,
				Name:     resolveItemName(gameID),
				Category: int(cat),
			}

			switch cat {
			case catWep:
				weapons = append(weapons, item)
			case catGadg:
				gadgets = append(gadgets, item)
			}
		}

		// Classify weapons
		for _, w := range weapons {
			if secondaryWeaponNames[w.Name] {
				if pl.SecondaryWeapon.GameID == 0 {
					pl.SecondaryWeapon = w
				}
			} else if w.Name != "" {
				pl.PrimaryWeapon = w
			}
		}
		if pl.PrimaryWeapon.GameID == 0 && len(weapons) > 0 {
			pl.PrimaryWeapon = weapons[len(weapons)-1]
		}
		if pl.SecondaryWeapon.GameID == 0 && len(weapons) > 1 {
			for _, w := range weapons {
				if w.GameID != pl.PrimaryWeapon.GameID {
					pl.SecondaryWeapon = w
					break
				}
			}
		}

		// Classify gadgets
		for _, g := range gadgets {
			if universalGadgetNames[g.Name] {
				if pl.SecondaryGadget.GameID == 0 {
					pl.SecondaryGadget = g
				}
			} else if g.Name != "" {
				pl.PrimaryGadget = g
			}
		}

		loadouts = append(loadouts, pl)
	}

	// Match to players by index order (loadout blocks appear in header player order)
	if len(loadouts) >= len(players) {
		for i := range loadouts {
			if i < len(players) {
				loadouts[i].PlayerIndex = i
			}
		}
	}

	return loadouts
}
