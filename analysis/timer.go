package analysis

import (
	"encoding/binary"
	"math"
)

// ExtractTimerTicks scans for round timer ticks.
// Pattern: 1F 07 EF C9 04 [seconds u32 LE]
func ExtractTimerTicks(data []byte) []TimerTick {
	pat := []byte{0x1F, 0x07, 0xEF, 0xC9}
	var ticks []TimerTick

	for i := 0; i+9 < len(data); i++ {
		if data[i] != pat[0] || data[i+1] != pat[1] || data[i+2] != pat[2] || data[i+3] != pat[3] {
			continue
		}
		if data[i+4] != 0x04 {
			continue
		}
		seconds := binary.LittleEndian.Uint32(data[i+5 : i+9])
		if seconds > 600 { // sanity: no round lasts > 10 minutes
			continue
		}
		ticks = append(ticks, TimerTick{
			Offset:  int64(i),
			Seconds: float32(seconds),
		})
	}

	return ticks
}

// BuildTimerPhases groups timer ticks into prep and action phases.
// A gap > 5 seconds between consecutive ticks marks a phase boundary.
func BuildTimerPhases(ticks []TimerTick) []TimerPhase {
	// Filter sentinels (seconds=0 at low offsets)
	var real []TimerTick
	for _, t := range ticks {
		if t.Offset > 1000 && t.Seconds > 0 {
			real = append(real, t)
		}
	}
	if len(real) < 2 {
		return nil
	}

	var phases []TimerPhase
	phaseStart := real[0]
	prevTick := real[0]

	for i := 1; i < len(real); i++ {
		gap := math.Abs(float64(real[i].Seconds - prevTick.Seconds))
		if gap > 5 {
			// Phase boundary
			dur := math.Abs(float64(phaseStart.Seconds - prevTick.Seconds))
			if dur >= 2 { // skip phases < 2s
				name := "prep"
				if len(phases) > 0 {
					name = "action"
				}
				phases = append(phases, TimerPhase{
					Name:     name,
					StartSec: phaseStart.Seconds,
					EndSec:   prevTick.Seconds,
					Duration: float32(dur),
				})
			}
			phaseStart = real[i]
		}
		prevTick = real[i]
	}

	// Final phase
	dur := math.Abs(float64(phaseStart.Seconds - prevTick.Seconds))
	if dur >= 2 {
		name := "action"
		if len(phases) == 0 {
			name = "prep"
		}
		phases = append(phases, TimerPhase{
			Name:     name,
			StartSec: phaseStart.Seconds,
			EndSec:   prevTick.Seconds,
			Duration: float32(dur),
		})
	}

	return phases
}

// RoundDurationFromTicks computes total round duration from timer phases.
func RoundDurationFromTicks(ticks []TimerTick) float32 {
	phases := BuildTimerPhases(ticks)
	total := float32(0)
	for _, p := range phases {
		total += p.Duration
	}
	return total
}

// AssignFrameTimes assigns elapsed time to position frames using linear
// offset-to-elapsed interpolation from timer ticks.
func AssignFrameTimes(tracks []*internalTrack, ticks []TimerTick, totalDuration float32) {
	if totalDuration <= 0 || len(tracks) == 0 {
		return
	}

	// Find min/max offsets across all frames
	minOff := int64(math.MaxInt64)
	maxOff := int64(0)
	for _, tr := range tracks {
		for _, f := range tr.Frames {
			if f.Offset < minOff {
				minOff = f.Offset
			}
			if f.Offset > maxOff {
				maxOff = f.Offset
			}
		}
	}

	if maxOff <= minOff {
		return
	}

	for _, tr := range tracks {
		for i := range tr.Frames {
			frac := float64(tr.Frames[i].Offset-minOff) / float64(maxOff-minOff)
			tr.Frames[i].TimeSecs = float32(frac * float64(totalDuration))
		}
	}
}

// AssignAmmoTimes assigns elapsed time to ammo events using offset interpolation.
func AssignAmmoTimes(events []AmmoEvent, ticks []TimerTick, totalDuration float32) {
	if len(events) == 0 || totalDuration <= 0 {
		return
	}

	minOff := int64(math.MaxInt64)
	maxOff := int64(0)
	for _, ev := range events {
		if ev.Offset < minOff {
			minOff = ev.Offset
		}
		if ev.Offset > maxOff {
			maxOff = ev.Offset
		}
	}

	if maxOff <= minOff {
		return
	}

	for i := range events {
		frac := float64(events[i].Offset-minOff) / float64(maxOff-minOff)
		events[i].TimeSecs = float32(frac * float64(totalDuration))
	}
}
