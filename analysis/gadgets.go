package analysis

import (
	"encoding/binary"
)

// SPAWN gadget hash identification.
//
// In addition to the SPAWN counter at +8 from the archetype, the SPAWN record
// carries gadget-identifying hashes at +60 and +64 from the archetype. These
// hashes disambiguate the SPECIFIC gadget instance behind a generic counter
// value (e.g. counter=142 covers both Mute Jammer and Frost Welcome Mat —
// the +60 hash tells you which).
//
// The lookup is two-level:
//   - For counter 146 (deployed gadget) the hash pair at (+60, +64) identifies
//     ADS-style multi-component gadgets (Jäger ADS, Melusi Banshee,
//     Thunderbird Kona, Mira Black Mirror).
//   - For other counters the +60 hash alone is the discriminator.

// Spawn-record byte offsets (relative to the 4-byte archetype pattern start):
const (
	spawnHashAOffset = 60
	spawnHashBOffset = 64
	spawnHashCOffset = 56 // some counters (126) put their hash at +56 instead of +60
)

// Counter-142 gadgets — identified by hashA at +60 from archetype.
var counter142Gadgets = map[uint32]string{
	0x2D1E3A9A: "Mute Jammer",
	0x2D1AAB9A: "Frost Welcome Mat",
	0xD2F8F39A: "Bandit Battery",
	0xFC72B39A: "Goyo Canister",
	0x2D1E3B16: "Nitro Cell",
}

// Counter-146 gadgets — multi-component, identified by (hashA, hashB) at (+60, +64).
type hashPair struct {
	A, B uint32
}

var counter146Gadgets = map[hashPair]string{
	{0x133B519A, 0x0CC9B9B2}: "Thunderbird Kóna Station",
	{0x133B519A, 0x4F01B6B2}: "Melusi Banshee",
	{0x133B519A, 0x2D1C4FB2}: "Jäger ADS",
	{0x1CA56E9A, 0x2D1DAE35}: "Mira Black Mirror",
}

// Counter-138 gadgets (overlaps with primary-weapon-drop classification —
// the +60 hash disambiguates).
var counter138Gadgets = map[uint32]string{
	0x9B72AE9A: "Azami Kiba Barrier",
}

// Counter-150 gadgets.
var counter150Gadgets = map[uint32]string{
	0x1CA56E9A: "Deployable Shield",
}

// Counter-126 gadgets — hash at +56.
var counter126Gadgets = map[uint32]string{
	0x45324600: "Alibi Prisma",
}

// allGadgetHashesA is the union of every known +60-offset gadget hash across
// all counter values. Used in the counter-independent scan path.
var allGadgetHashesA = func() map[uint32]string {
	out := make(map[uint32]string)
	for h, n := range counter142Gadgets {
		out[h] = n
	}
	for h, n := range counter138Gadgets {
		out[h] = n
	}
	for h, n := range counter150Gadgets {
		out[h] = n
	}
	for h, n := range counter126Gadgets {
		out[h] = n
	}
	return out
}()

// ExtractSpawnGadgetHashes walks the binary for documented gadget-identifying
// hashes and attributes each one to the nearest preceding SPAWN archetype's
// entity ref. The historical "counter-gated" path doesn't work for Y11S1+
// (counter byte at +8 reads as 0 across all 372 SPAWN matches), so this
// path is counter-INDEPENDENT: find a known gadget hash, look backward up to
// 70 bytes for the SPAWN pattern, read the entity ref at pattern-12.
//
// counters map is accepted for compatibility but currently unused.
func ExtractSpawnGadgetHashes(data []byte, counters map[uint32]uint32) map[uint32]string {
	_ = counters
	result := make(map[uint32]string)
	if len(data) < 100 {
		return result
	}
	pat := [4]byte{0x61, 0x73, 0x85, 0xFE}

	// Single-hash gadgets at +60 (counter-142/138/150) and +56 (counter-126).
	scanSingle := func(targetHashes map[uint32]string, offsetFromArchetype int) {
		for i := 16; i+4 < len(data); i++ {
			if i+4 > len(data) {
				break
			}
			h := binary.LittleEndian.Uint32(data[i : i+4])
			name, ok := targetHashes[h]
			if !ok {
				continue
			}
			// The hash is at offsetFromArchetype past the SPAWN pattern.
			archeStart := i - offsetFromArchetype
			if archeStart < 16 || archeStart+4 > len(data) {
				continue
			}
			if data[archeStart] != pat[0] || data[archeStart+1] != pat[1] ||
				data[archeStart+2] != pat[2] || data[archeStart+3] != pat[3] {
				continue
			}
			eid := binary.LittleEndian.Uint32(data[archeStart-12 : archeStart-8])
			if eid>>24 < 0xF0 && eid>>24 != 0 {
				// allow low-id non-player entities
			}
			if _, already := result[eid]; already {
				continue
			}
			result[eid] = name
		}
	}
	scanSingle(allGadgetHashesA, spawnHashAOffset)
	scanSingle(counter126Gadgets, spawnHashCOffset)

	// Multi-component (counter-146) gadgets: hashA at +60, hashB at +64.
	for i := 16; i+4 < len(data); i++ {
		hA := binary.LittleEndian.Uint32(data[i : i+4])
		// Quick filter: hashA must be one of the known multi-component values.
		isA := false
		for ab := range counter146Gadgets {
			if ab.A == hA {
				isA = true
				break
			}
		}
		if !isA {
			continue
		}
		if i+8 > len(data) {
			continue
		}
		hB := binary.LittleEndian.Uint32(data[i+4 : i+8])
		name, ok := counter146Gadgets[hashPair{hA, hB}]
		if !ok {
			continue
		}
		archeStart := i - spawnHashAOffset
		if archeStart < 16 || archeStart+4 > len(data) {
			continue
		}
		if data[archeStart] != pat[0] || data[archeStart+1] != pat[1] ||
			data[archeStart+2] != pat[2] || data[archeStart+3] != pat[3] {
			continue
		}
		eid := binary.LittleEndian.Uint32(data[archeStart-12 : archeStart-8])
		if _, already := result[eid]; already {
			continue
		}
		result[eid] = name
	}
	return result
}

// Gadget-inventory count hashes (last 40% of file).
// Format near pattern: ... 0x23 [eid u32 LE] ... [hash u32 LE] [count u8 or u32] ...
const (
	hashPrimaryGadgetCount   uint32 = 0x4FBDD114
	hashSecondaryGadgetCount uint32 = 0x44186B66
)

// GadgetInventory holds per-player primary/secondary gadget counts read from
// the late-file inventory records.
type GadgetInventory struct {
	PlayerIndex    int    `json:"playerIndex"`
	EntityRef      uint32 `json:"entityRef,omitempty"`
	PrimaryCount   int    `json:"primaryCount"`
	SecondaryCount int    `json:"secondaryCount"`
}

// ExtractGadgetInventory scans the binary for gadget-inventory count records.
// Wire format (TLV):
//
//	[0x22 marker] [hash u32 LE = 0x4FBDD114 or 0x44186B66] [0x04 type byte] [count u32 LE]
//
// Both hashes occur in the early header region (template records with count=0)
// AND in the late-file inventory region (real per-player counts). We scan the
// whole file and keep the MAXIMUM non-zero value per (player, slot).
//
// The owning player-entity ref is found by scanning backward up to 30 bytes for
// a 0x22 or 0x23 marker followed by an F0-prefix uint32.
func ExtractGadgetInventory(data []byte, entityToPlayer map[uint32]int) []GadgetInventory {
	if len(data) < 100 {
		return nil
	}

	// Records are stored per-entity-ref (not per-player) because the inventory
	// records reference WEAPON/GADGET entities rather than player entities. The
	// caller is expected to resolve entity ref → owning player using the
	// library's Loadouts table (each player's Primary/Secondary WeaponInfo
	// carries an EntityRef).
	perEntity := make(map[uint32]*GadgetInventory)
	for i := 16; i+9 <= len(data); i++ {
		h := binary.LittleEndian.Uint32(data[i : i+4])
		if h != hashPrimaryGadgetCount && h != hashSecondaryGadgetCount {
			continue
		}
		// TLV: [hash 4B] [type 0x04] [count u32 LE].
		if data[i+4] != 0x04 {
			continue
		}
		count := int(binary.LittleEndian.Uint32(data[i+5 : i+9]))
		if count == 0 || count > 16 {
			continue
		}

		// Find owning entity ref: scan backward up to 128 bytes for a marker byte
		// (0x22 or 0x23) followed by an F0-prefix uint32. The doc said 30 bytes
		// but empirically the entity ref sits ~95 bytes back in the property
		// record (followed by other TLV fields before the count hash).
		var eid uint32
		var eidPos = -1
		searchStart := i - 128
		if searchStart < 0 {
			searchStart = 0
		}
		// Walk backward and take the CLOSEST F0-prefix candidate (most recent).
		for j := i - 5; j >= searchStart; j-- {
			if j+5 > len(data) {
				continue
			}
			if data[j] == 0x22 || data[j] == 0x23 {
				cand := binary.LittleEndian.Uint32(data[j+1 : j+5])
				if cand>>24 >= 0xF0 {
					eid = cand
					eidPos = j
					break
				}
			}
		}
		_ = eidPos
		if eid == 0 {
			continue
		}
		// Most inventory records reference a child-entity (the inventory slot itself)
		// not the player entity directly. If entityToPlayer doesn't have it, we
		// still emit a record with PlayerIndex=-1 but the EntityRef carried so a
		// downstream consumer can resolve it.
		pIdx, ok := entityToPlayer[eid]
		if !ok {
			pIdx = -1
		}
		gi, exists := perEntity[eid]
		if !exists {
			gi = &GadgetInventory{PlayerIndex: pIdx, EntityRef: eid}
			perEntity[eid] = gi
		} else if pIdx >= 0 {
			// Player attribution may have been unknown at first sight; update if learned.
			gi.PlayerIndex = pIdx
		}
		switch h {
		case hashPrimaryGadgetCount:
			if count > gi.PrimaryCount {
				gi.PrimaryCount = count
			}
		case hashSecondaryGadgetCount:
			if count > gi.SecondaryCount {
				gi.SecondaryCount = count
			}
		}
	}

	out := make([]GadgetInventory, 0, len(perEntity))
	for _, gi := range perEntity {
		out = append(out, *gi)
	}
	return out
}

// LabelDamageRate maps a damage rate value (from health update sub-property
// 0x475BB68B) to a human-readable hit type.
//
//   0.067 → "dot" (gas/poison/bleed tick)
//   0.133 → "bullet"
//   other → "" (unknown / not applicable)
//
// Tolerance ±0.005 to allow for f32 noise.
func LabelDamageRate(rate float32) string {
	switch {
	case rate >= 0.062 && rate <= 0.072:
		return "dot"
	case rate >= 0.128 && rate <= 0.138:
		return "bullet"
	}
	return ""
}

// FC-UPDATE flag fingerprints for projectile sub-classification.
// These are read from the type-code field of FC-UPDATE packets (u16 at
// patternStart+4) accumulated across an entity's packet stream.
const (
	FlagGrapple    uint16 = 0x0280 // grapple line projectile
	FlagImpact     uint16 = 0x07C0 // impact grenade
	FlagImpactInit uint16 = 0x1FC0 // first-flag-only impact marker
	FlagThrown1    uint16 = 0x0380 // thrown projectile (one of three present)
	FlagThrown2    uint16 = 0x07C0 // (same as Impact — coincides with Thrown set)
	FlagThrown3    uint16 = 0x3FC0 // thrown projectile (final flag)
	FlagBarricade  uint16 = 0x1FE0 // barricade entity confirmation
	Flag0440       uint16 = 0x0440 // property-only packet, used for gadget fingerprinting
	Flag03C0       uint16 = 0x03C0 // pairs with 0x0440 size to discriminate Lesion/Kaid
)

// ClassifyProjectileSubType returns a projectile sub-type label based on the
// SET of FC-UPDATE flags observed across an entity's packets. The flag set is
// the union of all type-codes seen for that entity.
func ClassifyProjectileSubType(flagSet map[uint16]int) string {
	hasGrapple := flagSet[FlagGrapple] > 0
	hasImpact := flagSet[FlagImpact] > 0
	hasImpactInit := flagSet[FlagImpactInit] > 0
	hasThrown1 := flagSet[FlagThrown1] > 0
	hasThrown3 := flagSet[FlagThrown3] > 0

	switch {
	case hasThrown1 && hasImpact && hasThrown3:
		return "thrown"
	case hasGrapple:
		return "grapple"
	case hasImpactInit && hasImpact:
		return "impact_grenade"
	}
	return ""
}

// ClassifyGadgetByFlag uses 0x0440 packet size + 0x03C0 flag presence to
// distinguish Alibi Prisma / Lesion Gu Mine / Kaid Electroclaw.
//
//	0x0440 packet payload size == 24 + frameCount > 200  → Alibi Prisma
//	0x0440 packet payload size == 21 + 0x03C0 present     → Lesion Gu Mine
//	0x0440 packet payload size == 21 + no 0x03C0          → Kaid Rtila
func ClassifyGadgetByFlag(packetSizes []int, has03C0 bool, frameCount int) string {
	// Find dominant 0x0440 size.
	if len(packetSizes) == 0 {
		return ""
	}
	sizeCount := map[int]int{}
	for _, sz := range packetSizes {
		sizeCount[sz]++
	}
	bestSize, bestN := 0, 0
	for sz, c := range sizeCount {
		if c > bestN {
			bestN = c
			bestSize = sz
		}
	}
	switch bestSize {
	case 24:
		if frameCount > 200 {
			return "Alibi Prisma"
		}
	case 21:
		if has03C0 {
			return "Lesion Gu Mine"
		}
		return "Kaid Rtila Electroclaw"
	}
	return ""
}
