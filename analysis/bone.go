package analysis

import (
	"bytes"
	"encoding/binary"
	"math"
)

// Bone Magic markers
var (
	boneMagicA = []byte{0x02, 0x00, 0x70, 0x88, 0x98, 0x58} // head bone
	boneMagicB = []byte{0x00, 0x2C, 0x36, 0x14, 0x9B}       // chest bone
)

// ExtractBoneData scans for BMA (head) and BMB (chest) bone data within
// FC-UPDATE movement packets and attaches them to the nearest position frame.
//
// BMA Section A (36 bytes after magic):
//
//	[headOffX f32][headOffY f32][headOffZ f32][1.0 separator]
//	[aimQx f32][aimQy f32][aimQz f32][aimQw f32][1.0 separator]
//
// BMB Section B (36 bytes after magic):
//
//	[chestOffX f32][chestOffY f32][chestOffZ f32][1.0 separator]
//	[chestQx f32][chestQy f32][chestQz f32][chestQw f32][1.0 separator]
func ExtractBoneData(data []byte, tracks []*internalTrack) {
	if len(data) < 100 || len(tracks) == 0 {
		return
	}

	// Build entity → track index + frame index for nearest-offset lookup
	entityFrames := make(map[uint32][]boneFrameRef)
	for ti := range tracks {
		for fi := range tracks[ti].Frames {
			entityFrames[tracks[ti].EntityID] = append(
				entityFrames[tracks[ti].EntityID],
				boneFrameRef{ti, fi})
		}
	}

	archetypeFC := []byte{0x60, 0x73, 0x85, 0xFE}

	// Scan for BMA (head bone)
	for i := 0; i+6+36 <= len(data); i++ {
		if data[i] != 0x02 || !bytes.Equal(data[i:i+6], boneMagicA) {
			continue
		}

		payloadOff := i + 6
		if payloadOff+36 > len(data) {
			continue
		}

		hoX := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4]))
		hoY := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8]))
		hoZ := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12]))

		// Validate head offsets (should be small, < 2m)
		if absF(hoX) > 2 || absF(hoY) > 2 || absF(hoZ) > 2 {
			continue
		}

		// Separator should be ~1.0
		sep := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+12 : payloadOff+16]))
		if sep < 0.99 || sep > 1.01 {
			continue
		}

		qx := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+16 : payloadOff+20]))
		qy := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+20 : payloadOff+24]))
		qz := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+24 : payloadOff+28]))
		qw := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+28 : payloadOff+32]))

		if !isUnitQuat(qx, qy, qz, qw) {
			continue
		}

		// Find enclosing FC-UPDATE entity by scanning backward for archetype marker
		entityRef := findEnclosingEntity(data, i, archetypeFC)
		if entityRef == 0 {
			continue
		}

		// Find nearest frame for this entity
		refs, ok := entityFrames[entityRef]
		if !ok || len(refs) == 0 {
			continue
		}

		bestRef := findNearestFrame(refs, int64(i), tracks)
		if bestRef.trackIdx < 0 {
			continue
		}

		f := &tracks[bestRef.trackIdx].Frames[bestRef.frameIdx]
		f.HeadOffX = hoX
		f.HeadOffY = hoY
		f.HeadOffZ = hoZ
		f.HeadQX = qx
		f.HeadQY = qy
		f.HeadQZ = qz
		f.HeadQW = qw
	}

	// Scan for BMB (chest bone)
	for i := 0; i+5+36 <= len(data); i++ {
		if data[i] != 0x00 || !bytes.Equal(data[i:i+5], boneMagicB) {
			continue
		}

		payloadOff := i + 5
		if payloadOff+36 > len(data) {
			continue
		}

		coX := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4]))
		coY := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8]))
		coZ := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12]))

		if absF(coX) > 2 || absF(coY) > 2 || absF(coZ) > 2 {
			continue
		}

		sep := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+12 : payloadOff+16]))
		if sep < 0.99 || sep > 1.01 {
			continue
		}

		cqx := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+16 : payloadOff+20]))
		cqy := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+20 : payloadOff+24]))
		cqz := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+24 : payloadOff+28]))
		cqw := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+28 : payloadOff+32]))

		if !isUnitQuat(cqx, cqy, cqz, cqw) {
			continue
		}

		entityRef := findEnclosingEntity(data, i, archetypeFC)
		if entityRef == 0 {
			continue
		}

		refs, ok := entityFrames[entityRef]
		if !ok || len(refs) == 0 {
			continue
		}

		bestRef := findNearestFrame(refs, int64(i), tracks)
		if bestRef.trackIdx < 0 {
			continue
		}

		f := &tracks[bestRef.trackIdx].Frames[bestRef.frameIdx]
		f.ChestOffX = coX
		f.ChestOffY = coY
		f.ChestOffZ = coZ
		f.ChestQX = cqx
		f.ChestQY = cqy
		f.ChestQZ = cqz
		f.ChestQW = cqw
	}
}

// findEnclosingEntity scans backward from offset to find the FC-UPDATE
// archetype pattern and extract the entity ref 12 bytes before it.
func findEnclosingEntity(data []byte, offset int, archetype []byte) uint32 {
	// Scan backward up to 2000 bytes
	start := offset - 2000
	if start < 16 {
		start = 16
	}
	for j := offset; j >= start; j-- {
		if j+4 > len(data) {
			continue
		}
		if bytes.Equal(data[j:j+4], archetype) {
			// Entity ref at j-12
			if j >= 12 {
				ref := binary.LittleEndian.Uint32(data[j-12 : j-8])
				if ref>>24 >= 0xF0 {
					return ref
				}
			}
			return 0
		}
	}
	return 0
}

type boneFrameRef struct {
	trackIdx int
	frameIdx int
}

func findNearestFrame(refs []boneFrameRef, targetOff int64, tracks []*internalTrack) boneFrameRef {
	best := boneFrameRef{trackIdx: -1}
	bestDist := int64(math.MaxInt64)

	for _, ref := range refs {
		f := tracks[ref.trackIdx].Frames[ref.frameIdx]
		d := abs64(f.Offset - targetOff)
		if d < bestDist {
			bestDist = d
			best = boneFrameRef{ref.trackIdx, ref.frameIdx}
		}
	}

	return best
}

func absF(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
