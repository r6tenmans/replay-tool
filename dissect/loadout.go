package dissect

import (
	"encoding/binary"

	"github.com/rs/zerolog/log"
)

// AmmoUpdate represents an ammo state update for a player's weapon.
type AmmoUpdate struct {
	Available     uint32  `json:"available"`
	Capacity      uint32  `json:"capacity"`
	Hash1         uint32  `json:"hash1"`
	Hash2         uint32  `json:"hash2"`
	PlayerIndex   int     `json:"playerIndex"` // -1 if unmapped
	Time          string  `json:"time"`
	TimeInSeconds float64 `json:"timeInSeconds"`
	BinOffset     int     `json:"binOffset,omitempty"` // byte offset in decompressed stream
	weaponRef     uint32  // internal: weapon entity ref for player mapping
}

// readAmmo parses ammo/loadout data from the ammo pattern (77 CA 96 DE).
//
// Packet layout (bytes after pattern):
//
//	0x04 [uint32 available] 0x22 [4B player/property hash] 0x04 [uint32 capacity] 0x22 [4B gear hash] 0x04 [uint32 unknown]
//
// The 4-byte fields after 0x22 markers are property hashes, not direct DissectIDs.
// Player identification: the weapon entity ref at offset -8 from the pattern is
// mapped to players via first-occurrence ordering in buildWeaponMap().
func readAmmo(r *Reader) error {
	startOffset := r.offset // first byte after the 4-byte pattern

	// Extract weapon entity ref from 8 bytes before pattern start
	weaponRef := uint32(0)
	if startOffset >= 12 {
		weaponRef = binary.LittleEndian.Uint32(r.b[startOffset-12 : startOffset-8])
	}

	// Read type byte, expect 0x04 (uint32 type indicator)
	typeByte, err := r.Bytes(1)
	if err != nil {
		return nil
	}
	if typeByte[0] != 0x04 {
		return nil
	}

	// Read available ammo (uint32 LE, no leading type byte since we already consumed it)
	availBytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}
	available := uint32(availBytes[0]) | uint32(availBytes[1])<<8 | uint32(availBytes[2])<<16 | uint32(availBytes[3])<<24

	// Read 0x22 marker
	marker, err := r.Bytes(1)
	if err != nil {
		return nil
	}
	if marker[0] != 0x22 {
		return nil
	}

	// Read 4-byte property hash1
	h1Bytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}
	hash1 := uint32(h1Bytes[0]) | uint32(h1Bytes[1])<<8 | uint32(h1Bytes[2])<<16 | uint32(h1Bytes[3])<<24

	// Read 0x04 marker
	typeByte2, err := r.Bytes(1)
	if err != nil {
		return nil
	}
	if typeByte2[0] != 0x04 {
		return nil
	}

	// Read capacity (uint32 LE)
	capBytes, err := r.Bytes(4)
	if err != nil {
		return nil
	}
	capacity := uint32(capBytes[0]) | uint32(capBytes[1])<<8 | uint32(capBytes[2])<<16 | uint32(capBytes[3])<<24

	// Read optional hash2: 0x22 [4B hash2]
	hash2 := uint32(0)
	if r.offset+5 <= len(r.b) && r.b[r.offset] == 0x22 {
		r.Bytes(1) // skip 0x22 marker
		h2Bytes, err := r.Bytes(4)
		if err == nil {
			hash2 = uint32(h2Bytes[0]) | uint32(h2Bytes[1])<<8 | uint32(h2Bytes[2])<<16 | uint32(h2Bytes[3])<<24
		}
	}

	update := AmmoUpdate{
		Available:     available,
		Capacity:      capacity,
		Hash1:         hash1,
		Hash2:         hash2,
		PlayerIndex:   -1, // resolved after Read() via buildWeaponMap
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
		BinOffset:     startOffset,
		weaponRef:     weaponRef,
	}
	r.AmmoUpdates = append(r.AmmoUpdates, update)

	log.Debug().
		Uint32("available", available).
		Uint32("capacity", capacity).
		Uint32("hash1", hash1).
		Uint32("hash2", hash2).
		Uint32("weaponRef", weaponRef).
		Str("time", r.timeRaw).
		Msg("ammo")

	return nil
}
