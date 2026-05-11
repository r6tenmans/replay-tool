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
// FC-UPDATE movement packets and attaches them to the position frame from the
// SAME packet.
//
// REFACTORED: walks each BMA hit and binds it to the FIRST FC-UPDATE pattern
// found within 500 bytes BACKWARD (the parent packet). Each FC-UPDATE owns
// at most one BMA. Once a BMA is consumed by an FC-UPDATE, subsequent BMAs
// look for a NEW (later) parent packet. Tighter than the original 2000-byte
// backward search and prevents one FC-UPDATE from claiming multiple BMAs.
//
// Spec for in-packet layout:
//
//	BMA at offset i:
//	  [i:i+6]     = 02 00 70 88 98 58   (head magic)
//	  [i+6:i+18]  = head offset XYZ (|x|,|y|,|z| < 2)
//	  [i+18:i+22] = separator 1.0
//	  [i+22:i+38] = aim quaternion (unit)
//	  [i+38:i+42] = separator 1.0
//
//	BMB IMMEDIATELY AFTER BMA — within [BMAstart+36, BMAstart+46]:
//	  [j:j+5]     = 00 2C 36 14 9B      (chest magic)
//	  [j+5:j+17]  = chest offset XYZ
//	  [j+17:j+21] = separator 1.0
//	  [j+21:j+37] = chest quaternion
//	  [j+37:j+41] = separator 1.0
//
// pktSize at offset-8 from FC-UPDATE pattern is NOT reliable in Y11S1 binaries
// (always 0 across 106 K packets in observed data), so we use a fixed-size
// backward search window instead.
func ExtractBoneData(data []byte, tracks []*internalTrack) {
	if len(data) < 100 || len(tracks) == 0 {
		return
	}

	entityFrames := make(map[uint32][]boneFrameRef)
	for ti := range tracks {
		for fi := range tracks[ti].Frames {
			entityFrames[tracks[ti].EntityID] = append(
				entityFrames[tracks[ti].EntityID],
				boneFrameRef{ti, fi})
		}
	}

	pat := []byte{0x60, 0x73, 0x85, 0xFE}

	// First pass: collect all VALID FC-UPDATE packet starts. A valid packet has
	// an F0-prefix entity ref at -12 from the pattern (= startOffset-16 in the
	// dissect library's terminology, where startOffset = patternStart+4). The
	// raw `60 73 85 FE` pattern matches in many coincidental locations — filter
	// those out up front.
	type fcPacket struct {
		off       int
		entityRef uint32
	}
	var fcPackets []fcPacket
	for i := 16; i+10 < len(data); i++ {
		if data[i] != pat[0] || data[i+1] != pat[1] || data[i+2] != pat[2] || data[i+3] != pat[3] {
			continue
		}
		// Entity ref at patternStart-12 (= library's startOffset-16).
		entityRef := binary.LittleEndian.Uint32(data[i-12 : i-8])
		if entityRef>>24 != 0xF0 {
			continue
		}
		fcPackets = append(fcPackets, fcPacket{i, entityRef})
	}

	// Walk every BMA candidate. For each, find the IMMEDIATE preceding valid
	// FC-UPDATE packet (binary search) within 500 bytes.
	const maxBackDistance = 500
	lastClaimedIdx := -1

	for i := 6; i+42 <= len(data); i++ {
		if data[i] != 0x02 || !bytes.Equal(data[i:i+6], boneMagicA) {
			continue
		}

		hoX, hoY, hoZ, qx, qy, qz, qw, okA := decodeBMAPayload(data, i)
		if !okA {
			continue
		}

		// Binary search for the latest fcPacket with off <= i, skipping any
		// already claimed (idx <= lastClaimedIdx).
		lo, hi := 0, len(fcPackets)
		for lo < hi {
			mid := (lo + hi) / 2
			if fcPackets[mid].off > i {
				hi = mid
			} else {
				lo = mid + 1
			}
		}
		idx := lo - 1
		// Walk back if this index is already claimed.
		for idx > lastClaimedIdx && fcPackets[idx].off > i {
			idx--
		}
		if idx <= lastClaimedIdx || idx < 0 {
			continue
		}
		fcStart := fcPackets[idx].off
		if i-fcStart > maxBackDistance {
			continue
		}
		entityRef := fcPackets[idx].entityRef

		refs, ok := entityFrames[entityRef]
		if !ok || len(refs) == 0 {
			continue
		}
		bestRef := findNearestFrame(refs, int64(fcStart), tracks)
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

		// BMB must IMMEDIATELY follow BMA within [BMAstart+36, BMAstart+46].
		chestSearchStart := i + 36
		chestSearchEnd := i + 46
		if chestSearchEnd+41 > len(data) {
			chestSearchEnd = len(data) - 41
		}
		for k := chestSearchStart; k <= chestSearchEnd && k+5 <= len(data); k++ {
			if data[k] != 0x00 || !bytes.Equal(data[k:k+5], boneMagicB) {
				continue
			}
			coX, coY, coZ, cqx, cqy, cqz, cqw, okB := decodeBMBPayload(data, k)
			if !okB {
				continue
			}
			f.ChestOffX = coX
			f.ChestOffY = coY
			f.ChestOffZ = coZ
			f.ChestQX = cqx
			f.ChestQY = cqy
			f.ChestQZ = cqz
			f.ChestQW = cqw
			break
		}

		lastClaimedIdx = idx
	}
}

// decodeBMAPayload validates the 36-byte head bone payload following BMA magic
// and returns the head offset XYZ + aim quaternion. okA=false on validation fail.
func decodeBMAPayload(data []byte, magicOff int) (hoX, hoY, hoZ, qx, qy, qz, qw float32, okA bool) {
	payloadOff := magicOff + 6
	if payloadOff+36 > len(data) {
		return
	}
	hoX = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4]))
	hoY = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8]))
	hoZ = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12]))
	if absF(hoX) > 2 || absF(hoY) > 2 || absF(hoZ) > 2 {
		return
	}
	sep := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+12 : payloadOff+16]))
	if sep < 0.99 || sep > 1.01 {
		return
	}
	qx = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+16 : payloadOff+20]))
	qy = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+20 : payloadOff+24]))
	qz = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+24 : payloadOff+28]))
	qw = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+28 : payloadOff+32]))
	if !isUnitQuat(qx, qy, qz, qw) {
		return
	}
	okA = true
	return
}

// decodeBMBPayload validates the 36-byte chest bone payload following BMB magic.
func decodeBMBPayload(data []byte, magicOff int) (coX, coY, coZ, cqx, cqy, cqz, cqw float32, okB bool) {
	payloadOff := magicOff + 5
	if payloadOff+36 > len(data) {
		return
	}
	coX = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff : payloadOff+4]))
	coY = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+4 : payloadOff+8]))
	coZ = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+8 : payloadOff+12]))
	if absF(coX) > 2 || absF(coY) > 2 || absF(coZ) > 2 {
		return
	}
	sep := math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+12 : payloadOff+16]))
	if sep < 0.99 || sep > 1.01 {
		return
	}
	cqx = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+16 : payloadOff+20]))
	cqy = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+20 : payloadOff+24]))
	cqz = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+24 : payloadOff+28]))
	cqw = math.Float32frombits(binary.LittleEndian.Uint32(data[payloadOff+28 : payloadOff+32]))
	if !isUnitQuat(cqx, cqy, cqz, cqw) {
		return
	}
	okB = true
	return
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

// ComputeHeadWorldAim computes world-space head aim angles for every frame that
// has both a head bone quaternion and a body orientation.
//
// head_world = body_quat × head_local_quat (Hamilton product, parent × child)
//
// For library-path frames where body quaternion fields are zero, the body
// quaternion is reconstructed from YawDeg/PitchDeg using ZXY Euler convention.
func ComputeHeadWorldAim(tracks []*internalTrack) {
	for _, tr := range tracks {
		for i := range tr.Frames {
			f := &tr.Frames[i]
			if !isUnitQuat(f.HeadQX, f.HeadQY, f.HeadQZ, f.HeadQW) {
				continue
			}
			bx, by, bz, bw := f.Qx, f.Qy, f.Qz, f.Qw
			if !isUnitQuat(bx, by, bz, bw) {
				// Reconstruct body quaternion from yaw/pitch (ZXY intrinsic)
				if f.YawDeg == 0 && f.PitchDeg == 0 {
					continue
				}
				bx, by, bz, bw = quatFromYawPitch(f.YawDeg, f.PitchDeg)
			}
			// World-space head = body × head_local
			hx, hy, hz, hw := multiplyQuat(bx, by, bz, bw, f.HeadQX, f.HeadQY, f.HeadQZ, f.HeadQW)
			f.HeadAimYaw = calcYawFull(hx, hy, hz, hw)
			f.HeadAimPitch = calcPitch(hx, hy, hz, hw)
		}
	}
}

// quatFromYawPitch builds a quaternion for ZXY Euler rotation (yaw around Z,
// then pitch around X) — matching the convention used by calcYawFull/calcPitch.
func quatFromYawPitch(yawDeg, pitchDeg float32) (x, y, z, w float32) {
	yaw := float64(yawDeg) * math.Pi / 180
	pitch := float64(pitchDeg) * math.Pi / 180
	sy, cy := math.Sin(yaw/2), math.Cos(yaw/2)
	sp, cp := math.Sin(pitch/2), math.Cos(pitch/2)
	// q = q_z(yaw) × q_x(pitch)
	return float32(cy * sp), float32(sy * sp), float32(sy * cp), float32(cy * cp)
}

// multiplyQuat returns the Hamilton product a × b.
func multiplyQuat(ax, ay, az, aw, bx, by, bz, bw float32) (float32, float32, float32, float32) {
	return aw*bx + ax*bw + ay*bz - az*by,
		aw*by - ax*bz + ay*bw + az*bx,
		aw*bz + ax*by - ay*bx + az*bw,
		aw*bw - ax*bx - ay*by - az*bz
}

func absF(x float32) float32 {
	if x < 0 {
		return -x
	}
	return x
}
