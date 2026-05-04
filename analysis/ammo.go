package analysis

import (
	"sort"
)

// ammoPattern is the 4-byte marker for ammo events: 77 CA 96 DE.
var ammoPattern = []byte{0x77, 0xCA, 0x96, 0xDE}

// ExtractAmmoEvents scans for ammo state events in the binary.
// Each event: [weapon_eid 4B] [00 00 00 00] [77 CA 96 DE] [TLV fields...]
// TLV: [04] [value u32 LE] [22 or 23] [hash u32 LE]
func ExtractAmmoEvents(data []byte) []AmmoEvent {
	if len(data) < 20 {
		return nil
	}

	var events []AmmoEvent

	for i := 8; i+4 <= len(data); i++ {
		if data[i] != 0x77 || data[i+1] != 0xCA || data[i+2] != 0x96 || data[i+3] != 0xDE {
			continue
		}

		// Zero padding at -4, weapon EID at -8
		if u32(data, i-4) != 0 {
			continue
		}
		weaponEID := u32(data, i-8)
		if weaponEID == 0 {
			continue
		}

		ev := AmmoEvent{
			Offset:    int64(i),
			WeaponEID: weaponEID,
		}

		// Parse TLV fields
		pos := i + 4
		for fieldCount := 0; fieldCount < 8 && pos+9 < len(data); fieldCount++ {
			if data[pos] != 0x04 {
				break
			}
			value := u32(data, pos+1)
			tag := data[pos+5]
			if tag != 0x22 && tag != 0x23 {
				break
			}
			hash := u32(data, pos+6)

			// Skip F0-prefix entity IDs masquerading as hashes
			if hash>>24 >= 0xF0 {
				pos += 10
				continue
			}

			ev.Fields = append(ev.Fields, AmmoField{Value: value, Hash: hash})
			pos += 10
		}

		if len(ev.Fields) > 0 {
			events = append(events, ev)
		}
	}

	return events
}

// BuildWeaponTracking maps ammo events to players, classifies weapons,
// and computes shot counts.
func BuildWeaponTracking(data []byte, ammoEvents []AmmoEvent, players []PlayerInfo,
	entityToPlayer map[uint32]int) map[int]*PlayerWeapons {

	result := make(map[int]*PlayerWeapons)
	if len(ammoEvents) == 0 || len(players) == 0 {
		return result
	}

	// Collect unique weapon EIDs
	ammoWeaponEIDs := make(map[uint32]bool)
	for _, ev := range ammoEvents {
		ammoWeaponEIDs[ev.WeaponEID] = true
	}

	// Map weapon EIDs to players via init blocks
	weaponToPlayer := mapWeaponEIDsToPlayers(data, ammoWeaponEIDs, len(players), players)

	// Aggregate per-weapon
	type weaponAgg struct {
		eid        uint32
		events     []AmmoEvent
		loadedAmmo int
		grandTotal int
		shotsFired int
		finalMag   int
	}
	weaponMap := make(map[uint32]*weaponAgg)

	for _, ev := range ammoEvents {
		agg, ok := weaponMap[ev.WeaponEID]
		if !ok {
			agg = &weaponAgg{eid: ev.WeaponEID}
			weaponMap[ev.WeaponEID] = agg
		}
		agg.events = append(agg.events, ev)
		for _, f := range ev.Fields {
			switch f.Hash {
			case AmmoHashLoadedAmmo:
				if agg.loadedAmmo == 0 {
					agg.loadedAmmo = int(f.Value)
				}
			case AmmoHashGrandTotal:
				if agg.grandTotal == 0 {
					agg.grandTotal = int(f.Value)
				}
			}
		}
	}

	// Count shots (current-mag decrements)
	for _, agg := range weaponMap {
		prevAmmo := -1
		for _, ev := range agg.events {
			for _, f := range ev.Fields {
				if f.Hash == AmmoHashCurrentMag {
					cur := int(f.Value)
					if prevAmmo >= 0 && cur < prevAmmo {
						agg.shotsFired += prevAmmo - cur
					}
					agg.finalMag = cur
					prevAmmo = cur
				}
			}
		}
	}

	// Build per-player weapon info
	playerWeapons := make(map[int][]WeaponAmmoInfo)

	for eid, agg := range weaponMap {
		pIdx, mapped := weaponToPlayer[eid]
		info := WeaponAmmoInfo{
			WeaponEID:    eid,
			PlayerIndex:  pIdx,
			MagazineSize: agg.loadedAmmo,
			InitialAmmo:  agg.grandTotal,
			FinalAmmo:    agg.finalMag,
			ShotsFired:   agg.shotsFired,
			TotalEvents:  len(agg.events),
		}
		info.WeaponCategory = classifyWeaponByAmmo(info.InitialAmmo)

		if mapped {
			playerWeapons[pIdx] = append(playerWeapons[pIdx], info)
		}
	}

	// Classify primary/secondary per player
	for pIdx, weapons := range playerWeapons {
		sort.Slice(weapons, func(i, j int) bool {
			return weapons[i].InitialAmmo > weapons[j].InitialAmmo
		})
		if len(weapons) > 0 {
			weapons[0].IsPrimary = true
		}
		pw := &PlayerWeapons{
			PlayerIndex: pIdx,
			AllWeapons:  weapons,
		}
		if len(weapons) > 0 {
			w := weapons[0]
			pw.Primary = &w
		}
		if len(weapons) > 1 {
			w := weapons[1]
			pw.Secondary = &w
		}
		result[pIdx] = pw
	}

	return result
}

// mapWeaponEIDsToPlayers maps weapon entity IDs to players via init blocks.
// Pattern: 5F 85 CC 85 in the last 5% of the binary.
func mapWeaponEIDsToPlayers(data []byte, ammoWeaponEIDs map[uint32]bool,
	numPlayers int, players []PlayerInfo) map[uint32]int {

	result := make(map[uint32]int)
	if len(data) < 100 || numPlayers == 0 {
		return result
	}

	// Scan last 5% for weapon init blocks
	startOff := len(data) * 95 / 100

	type weaponHit struct {
		offset    int
		weaponEID uint32
	}
	seen := make(map[uint32]bool)
	var hits []weaponHit

	for i := startOff; i+20 <= len(data); i++ {
		if data[i] != 0x5F || data[i+1] != 0x85 || data[i+2] != 0xCC || data[i+3] != 0x85 {
			continue
		}

		var weaponEID uint32
		if data[i+4] == 0x1A && i+13 <= len(data) {
			weaponEID = u32(data, i+9)
		} else if data[i+4] == 0x22 && i+20 <= len(data) && data[i+5] == 0x14 {
			weaponEID = u32(data, i+16)
		}

		if weaponEID == 0 || weaponEID>>24 < 0xF0 {
			continue
		}
		if len(ammoWeaponEIDs) > 0 && !ammoWeaponEIDs[weaponEID] {
			continue
		}
		if seen[weaponEID] {
			continue
		}
		seen[weaponEID] = true
		hits = append(hits, weaponHit{offset: i, weaponEID: weaponEID})
	}

	if len(hits) < 2 {
		return result
	}

	// Split at largest gap (team boundary)
	maxGap := 0
	splitIdx := len(hits)
	for i := 1; i < len(hits); i++ {
		gap := hits[i].offset - hits[i-1].offset
		if gap > maxGap {
			maxGap = gap
			splitIdx = i
		}
	}

	// Count teams
	numTeam1 := 0
	for _, p := range players {
		if p.TeamIndex == 1 {
			numTeam1++
		}
	}
	numTeam0 := numPlayers - numTeam1

	cluster1 := hits[:splitIdx]
	cluster2 := hits[splitIdx:]

	assign := func(clusterHits []weaponHit, teamStart, teamSize int) {
		pairIdx := 0
		for i := 0; i < len(clusterHits) && pairIdx < teamSize; i += 2 {
			pIdx := teamStart + pairIdx
			result[clusterHits[i].weaponEID] = pIdx
			if i+1 < len(clusterHits) {
				result[clusterHits[i+1].weaponEID] = pIdx
			}
			pairIdx++
		}
	}

	assign(cluster1, 0, numTeam1)
	assign(cluster2, numTeam1, numTeam0)

	return result
}

func classifyWeaponByAmmo(totalAmmo int) string {
	switch {
	case totalAmmo >= 200:
		return "LMG"
	case totalAmmo >= 100:
		return "AR/SMG"
	case totalAmmo >= 50:
		return "Pistol/SMG"
	case totalAmmo >= 15:
		return "Sidearm"
	case totalAmmo > 0:
		return "Gadget"
	default:
		return ""
	}
}

// ReconstructShots detects ammo decreases and maps each shot to the
// nearest player position/aim direction at the moment of fire.
func ReconstructShots(ammoEvents []AmmoEvent, players []PlayerTrack,
	entityToPlayer map[uint32]int) []ShotEvent {

	if len(ammoEvents) == 0 || len(players) == 0 {
		return nil
	}

	// Build weapon → player mapping from ammo events
	// (already done in BuildWeaponTracking, but we need it here too)
	weaponToPlayer := make(map[uint32]int)
	for _, pt := range players {
		// Will be populated from the weapon tracking
		_ = pt
	}

	// Build per-player position index sorted by offset for temporal matching
	type posRef struct {
		x, y, z, yaw, pitch float32
		hqX, hqY, hqZ, hqW  float32
		offset              int64
		seq                 int
		timeSecs            float64
	}
	playerPositions := make(map[int][]posRef)
	for _, pt := range players {
		for i, f := range pt.Frames {
			if f.IsCamera {
				continue
			}
			playerPositions[pt.PlayerIndex] = append(playerPositions[pt.PlayerIndex], posRef{
				x: f.X, y: f.Y, z: f.Z, yaw: f.YawDeg, pitch: f.PitchDeg,
				hqX: f.HeadQX, hqY: f.HeadQY, hqZ: f.HeadQZ, hqW: f.HeadQW,
				offset: f.Offset, seq: i, timeSecs: float64(f.TimeSecs),
			})
		}
	}

	// Detect shots from ammo decreases
	var shots []ShotEvent
	type weaponState struct{ lastAmmo uint32 }
	states := make(map[uint32]weaponState)

	for _, ev := range ammoEvents {
		pIdx, ok := weaponToPlayer[ev.WeaponEID]
		if !ok {
			continue
		}

		var curAmmo uint32
		hasCurAmmo := false
		for _, f := range ev.Fields {
			if f.Hash == AmmoHashCurrentMag {
				curAmmo = f.Value
				hasCurAmmo = true
			}
		}
		if !hasCurAmmo {
			continue
		}

		prev, exists := states[ev.WeaponEID]
		states[ev.WeaponEID] = weaponState{curAmmo}
		if !exists {
			continue
		}
		if curAmmo >= prev.lastAmmo || prev.lastAmmo-curAmmo > 10 {
			continue
		}

		positions := playerPositions[pIdx]
		if len(positions) == 0 {
			continue
		}

		// Find nearest position by binary offset
		targetOff := ev.Offset
		bestIdx := 0
		bestDist := abs64(positions[0].offset - targetOff)
		for j := 1; j < len(positions); j++ {
			d := abs64(positions[j].offset - targetOff)
			if d < bestDist {
				bestDist = d
				bestIdx = j
			}
		}

		pos := positions[bestIdx]
		decrease := prev.lastAmmo - curAmmo
		for s := uint32(0); s < decrease; s++ {
			shots = append(shots, ShotEvent{
				PlayerIndex: pIdx,
				X:           pos.x, Y: pos.y, Z: pos.z,
				YawDeg: pos.yaw, PitchDeg: pos.pitch,
				HeadQX: pos.hqX, HeadQY: pos.hqY,
				HeadQZ: pos.hqZ, HeadQW: pos.hqW,
				TimeSecs: pos.timeSecs,
				Seq:      pos.seq,
			})
		}
	}

	return shots
}

func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
