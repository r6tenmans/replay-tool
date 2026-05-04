package analysis

import (
	"encoding/binary"
	"fmt"
	"math"
)

// ExtractCameraFrames detects camera look-direction packets (Pass 4).
// Signature: [0xa5b2f3a5 4B] [0x01 4B] [varies 4B] [0x02 4B] [qx qy qz qw]
// Entity ID found by scanning forward for archetype 0xFE857360.
func ExtractCameraFrames(data []byte, tracks []*internalTrack) {
	if len(data) < 100 {
		return
	}

	trackMap := make(map[uint32]*internalTrack)
	for _, tr := range tracks {
		trackMap[tr.EntityID] = tr
	}

	for i := 16; i+16 <= len(data); i += 4 {
		if u32(data, i-4) != 0x00000002 {
			continue
		}
		if u32(data, i-12) != 0x00000001 {
			continue
		}
		if u32(data, i-16) != 0xa5b2f3a5 {
			continue
		}

		qx := f32(data, i)
		qy := f32(data, i+4)
		qz := f32(data, i+8)
		qw := f32(data, i+12)

		if !isUnitQuat(qx, qy, qz, qw) {
			continue
		}

		// Find entity ID by scanning forward for archetype 0xFE857360
		var camEntityID uint32
		for off := i + 16; off < i+120 && off+4 <= len(data); off++ {
			if binary.LittleEndian.Uint32(data[off:off+4]) == 0xFE857360 {
				eOff := off - 12
				if eOff >= i+16 {
					camEntityID = binary.LittleEndian.Uint32(data[eOff : eOff+4])
				}
				break
			}
		}
		if camEntityID == 0 {
			continue
		}

		tr, ok := trackMap[camEntityID]
		if !ok {
			// Create new track for this camera entity
			hex := fmt.Sprintf("%02x %02x %02x %02x",
				byte(camEntityID), byte(camEntityID>>8),
				byte(camEntityID>>16), byte(camEntityID>>24))
			tr = &internalTrack{
				EntityID:  camEntityID,
				EntityHex: hex,
				TeamIndex: -1,
			}
			trackMap[camEntityID] = tr
			tracks = append(tracks, tr)
		}

		rawYaw := calcYawFull(qx, qy, qz, qw)
		pitchDeg := calcPitch(qx, qy, qz, qw)

		var lastX, lastY, lastZ, lastYaw float32
		if len(tr.Frames) > 0 {
			last := tr.Frames[len(tr.Frames)-1]
			lastX, lastY, lastZ, lastYaw = last.X, last.Y, last.Z, last.YawDeg
		}
		yaw := unwrapYaw(lastYaw, rawYaw)

		pf := PosFrame{
			Offset:   int64(i),
			EntityID: camEntityID,
			X:        lastX,
			Y:        lastY,
			Z:        lastZ,
			Qx:       qx,
			Qy:       qy,
			Qz:       qz,
			Qw:       qw,
			YawDeg:   yaw,
			PitchDeg: pitchDeg,
			IsCamera: true,
		}
		tr.Frames = append(tr.Frames, pf)
	}
}

// FilterCameraFrames removes camera frames from non-player entities
// (gadgets, weapons, barricades, projectiles). Only players and drones keep them.
func FilterCameraFrames(tracks []*internalTrack) {
	for _, tr := range tracks {
		if tr.EntityID>>24 >= 0xF0 {
			continue // player entities keep camera frames
		}
		if tr.SpawnCounter == 154 {
			continue // drones keep camera frames
		}
		// Strip camera frames from everything else
		n := 0
		for _, f := range tr.Frames {
			if !f.IsCamera {
				tr.Frames[n] = f
				n++
			}
		}
		tr.Frames = tr.Frames[:n]
	}
}

// ensure math is used
var _ = math.Pi
