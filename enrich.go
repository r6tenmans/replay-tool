package main

import (
	"sort"
	"strings"

	"github.com/wnc-replay/replay-tool/analysis"
	"github.com/wnc-replay/replay-tool/dissect"
)

// enrichAnalysis runs all the post-pipeline analytics that correlate already-extracted
// data into higher-value derived signals. None of these scan the binary directly —
// they operate on the structured outputs.
func enrichAnalysis(output *FullOutput, reader *dissect.Reader) {
	a := output.Analysis
	if a == nil {
		return
	}

	a.Hits = detectHits(a, output.Header.Players)
	a.ShotDamages = computeShotDamages(a.Hits)
	a.Trades = detectTrades(a, output.Header.Players)
	a.Reinforcements = locateReinforcements(a, output.Header.Players)
	a.SpectatorPeriods = buildSpectatorPeriods(a, output.Header.Players)
	a.BombPlant = detectBombPlant(a, output.Header.Players)
	a.BombSite = classifyBombSite(a, output.Header.Players)
	a.Outcome = computeRoundOutcome(a, output.Header)
	resolveSessionWeaponIDs(a, output.Header.Players)
}

// ============================================================
// 1. Hit detection: correlate shots with health drops in target
// ============================================================

const (
	hitWindowSecs    = 0.6 // shot-to-health-drop max latency (game tick + network jitter)
	hitMinDamage     = 1.0 // minimum hp delta to count as a hit
)

// detectHits identifies the killing/incapacitating shot for each kill+DBNO event.
//
// R6's binary only records HP at major transitions (spawn=100, DBNO<5, dead=0), so we
// can't see every individual hit. What we CAN do reliably: for each kill event (with
// known attacker→victim pair from MatchFeedback), find the attacker's last shot before
// the event time. That shot is the killing/incapacitating one.
func detectHits(a *analysis.RoundAnalysis, players []PlayerInfoHeader) []analysis.HitEvent {
	if len(a.LibraryShots) == 0 || len(a.GameEvents) == 0 {
		return nil
	}

	usernameIdx := make(map[string]int, len(players))
	for i, p := range players {
		usernameIdx[p.Username] = i
	}

	// Build per-shooter sorted shot list.
	type shotEntry struct {
		t    float32
		x, y, z float32
	}
	shotsByShooter := make(map[int][]shotEntry)
	for _, sh := range a.LibraryShots {
		if sh.PlayerIndex < 0 {
			continue
		}
		shotsByShooter[sh.PlayerIndex] = append(shotsByShooter[sh.PlayerIndex], shotEntry{
			t: float32(sh.TimeSecs), x: sh.X, y: sh.Y, z: sh.Z,
		})
	}
	for k := range shotsByShooter {
		sort.Slice(shotsByShooter[k], func(i, j int) bool { return shotsByShooter[k][i].t < shotsByShooter[k][j].t })
	}

	var hits []analysis.HitEvent
	for _, ge := range a.GameEvents {
		var attacker, victim string
		var isKill, isDBNO bool
		switch ge.Type {
		case "kill":
			parts := strings.SplitN(ge.Text, " killed ", 2)
			if len(parts) != 2 {
				continue
			}
			attacker, victim = parts[0], parts[1]
			isKill = true
		case "dbno":
			parts := strings.SplitN(ge.Text, " downed ", 2)
			if len(parts) != 2 {
				continue
			}
			attacker, victim = parts[0], parts[1]
			isDBNO = true
		default:
			continue
		}
		ai, ok1 := usernameIdx[attacker]
		vi, ok2 := usernameIdx[victim]
		if !ok1 || !ok2 {
			continue
		}
		shotList, ok := shotsByShooter[ai]
		if !ok {
			continue
		}
		// Find the latest shot at or before ge.TimeSecs (with a small leniency for clock drift).
		eventT := ge.TimeSecs + 1.0 // give a small forward window for clock drift
		idx := sort.Search(len(shotList), func(i int) bool { return shotList[i].t > eventT })
		if idx == 0 {
			continue
		}
		bestShot := shotList[idx-1]
		// Don't match shots from a previous lifetime (e.g., > 10s before the event is suspect).
		if eventT-bestShot.t > 10 {
			continue
		}
		hit := analysis.HitEvent{
			ShooterIndex: ai,
			VictimIndex:  vi,
			ShotTimeSecs: bestShot.t,
			HitTimeSecs:  ge.TimeSecs,
			Damage:       100, // assume full kill since we can't see intermediate damage
			HpAfter:      0,
			IsKill:       isKill,
			IsDBNO:       isDBNO,
			Headshot:     ge.Headshot,
			ShotX:        bestShot.x,
			ShotY:        bestShot.y,
			ShotZ:        bestShot.z,
		}
		if isDBNO {
			hit.Damage = 95 // DBNO transition = ~95 damage from full HP
			hit.HpAfter = 5
		}
		hits = append(hits, hit)
	}
	return hits
}

func computeShotDamages(hits []analysis.HitEvent) []analysis.ShotDamage {
	if len(hits) == 0 {
		return nil
	}
	out := make([]analysis.ShotDamage, 0, len(hits))
	for _, h := range hits {
		out = append(out, analysis.ShotDamage{
			ShooterIndex: h.ShooterIndex,
			VictimIndex:  h.VictimIndex,
			ShotTimeSecs: h.ShotTimeSecs,
			Damage:       h.Damage,
			IsKill:       h.IsKill,
		})
	}
	return out
}

// ============================================================
// 2. Trade kills: kill within tradeWindow of teammate's death
// ============================================================

const tradeWindowSecs = 5.0

func detectTrades(a *analysis.RoundAnalysis, players []PlayerInfoHeader) []analysis.TradeKill {
	if len(a.GameEvents) == 0 || len(players) == 0 {
		return nil
	}
	type kill struct {
		t              float32
		killer, victim int
	}
	var kills []kill
	usernameIdx := make(map[string]int, len(players))
	for i, p := range players {
		usernameIdx[p.Username] = i
	}
	for _, ge := range a.GameEvents {
		if ge.Type != "kill" {
			continue
		}
		// Parse "<killer> killed <victim>"
		parts := strings.SplitN(ge.Text, " killed ", 2)
		if len(parts) != 2 {
			continue
		}
		ki, ok1 := usernameIdx[parts[0]]
		vi, ok2 := usernameIdx[parts[1]]
		if !ok1 || !ok2 {
			continue
		}
		kills = append(kills, kill{ge.TimeSecs, ki, vi})
	}

	var trades []analysis.TradeKill
	for i, k := range kills {
		// Look for a prior kill of one of k.killer's teammates within tradeWindow.
		for j := i - 1; j >= 0; j-- {
			pk := kills[j]
			if k.t-pk.t > tradeWindowSecs {
				break
			}
			// k.killer is on the same team as pk.victim, and pk.killer == k.victim
			if pk.victim >= len(players) || k.killer >= len(players) {
				continue
			}
			if players[pk.victim].TeamIndex != players[k.killer].TeamIndex {
				continue
			}
			if pk.killer != k.victim {
				continue
			}
			trades = append(trades, analysis.TradeKill{
				TraderIndex:    k.killer,
				TradedForIndex: pk.victim,
				VictimIndex:    k.victim,
				TraderTimeSecs: k.t,
				TradedTimeSecs: pk.t,
				WindowSecs:     k.t - pk.t,
			})
			break
		}
	}
	return trades
}

// ============================================================
// 3. Reinforcement positions: locate the deployer's XYZ at each reinforce event
// ============================================================

func locateReinforcements(a *analysis.RoundAnalysis, players []PlayerInfoHeader) []analysis.ReinforceEvent {
	if len(a.LibraryGameActions) == 0 || len(a.Players) == 0 {
		return nil
	}
	// Collect reinforce events with their elapsed times.
	type reinforceTime struct {
		t      float32
		binOff int
	}
	var times []reinforceTime
	for _, ga := range a.LibraryGameActions {
		if ga.Type != "reinforce" {
			continue
		}
		times = append(times, reinforceTime{ga.TimeSecs, ga.BinOffset})
	}
	if len(times) == 0 {
		return nil
	}

	// The library emits a "reinforce" game action per binary state-change marker, which
	// can fire 4-5 times for a single wall reinforcement (per-segment) AND across multiple
	// players. Dedupe by clustering events within 1.5s into a single reinforcement, then
	// attribute each cluster to the nearest defender position.
	const clusterWindow = 1.5
	var clusters []reinforceTime
	for _, rt := range times {
		if len(clusters) > 0 && rt.t-clusters[len(clusters)-1].t < clusterWindow {
			continue
		}
		clusters = append(clusters, rt)
	}

	const matchWindow = 1.0
	var reinforces []analysis.ReinforceEvent
	for _, rt := range clusters {
		bestIdx := -1
		var bestDt float32 = matchWindow + 1
		var bestX, bestY, bestZ float32
		for _, pt := range a.Players {
			if pt.PlayerIndex >= len(players) || players[pt.PlayerIndex].IsAttack {
				continue
			}
			for _, f := range pt.Frames {
				if f.IsCamera || f.TimeSecs == 0 {
					continue
				}
				dt := f.TimeSecs - rt.t
				if dt < 0 {
					dt = -dt
				}
				if dt < bestDt {
					bestDt = dt
					bestIdx = pt.PlayerIndex
					bestX, bestY, bestZ = f.X, f.Y, f.Z
				}
			}
		}
		if bestIdx < 0 {
			continue
		}
		username := ""
		if bestIdx < len(players) {
			username = players[bestIdx].Username
		}
		reinforces = append(reinforces, analysis.ReinforceEvent{
			PlayerIndex: bestIdx,
			Username:    username,
			TimeSecs:    rt.t,
			X:           bestX,
			Y:           bestY,
			Z:           bestZ,
			BinOffset:   rt.binOff,
		})
	}
	// Cap at 10 (game-rule maximum: 5 defenders × 2 reinforcements each).
	if len(reinforces) > 10 {
		reinforces = reinforces[:10]
	}
	return reinforces
}

// ============================================================
// 4. Spectator POV periods: contiguous windows of recording-player camera target
// ============================================================

func buildSpectatorPeriods(a *analysis.RoundAnalysis, players []PlayerInfoHeader) []analysis.SpectatorPeriod {
	if len(a.CameraFrames) == 0 {
		return nil
	}
	// Camera frames in Y11S1 have BinOffsets below the first timer tick anchor, so their
	// TimeSecs values are mostly 0. Sort by binOffset (which IS monotonic with time) and
	// rebuild a synthetic time scale from the round duration.
	frames := make([]analysis.LibraryCameraFrame, 0, len(a.CameraFrames))
	for _, cf := range a.CameraFrames {
		if cf.PlayerIndex < 0 {
			continue
		}
		frames = append(frames, cf)
	}
	if len(frames) == 0 {
		return nil
	}
	sort.Slice(frames, func(i, j int) bool { return frames[i].BinOffset < frames[j].BinOffset })

	// Build a synthetic time per frame using min-max of BinOffset → roundDuration, but
	// only if all TimeSecs are zero (otherwise trust the existing values).
	useSynthetic := true
	for _, f := range frames {
		if f.TimeSecs > 0 {
			useSynthetic = false
			break
		}
	}
	if useSynthetic && a.RoundDuration > 0 {
		minOff := frames[0].BinOffset
		maxOff := frames[len(frames)-1].BinOffset
		if maxOff > minOff {
			for i := range frames {
				frac := float64(frames[i].BinOffset-minOff) / float64(maxOff-minOff)
				frames[i].TimeSecs = float32(frac * float64(a.RoundDuration))
			}
		}
	}

	const minGap = 2.0
	var periods []analysis.SpectatorPeriod
	currTarget := frames[0].PlayerIndex
	currStart := frames[0].TimeSecs
	currEnd := frames[0].TimeSecs
	currCount := 1
	flush := func() {
		username := ""
		if currTarget >= 0 && currTarget < len(players) {
			username = players[currTarget].Username
		}
		periods = append(periods, analysis.SpectatorPeriod{
			TargetIndex: currTarget,
			Username:    username,
			StartSecs:   currStart,
			EndSecs:     currEnd,
			FrameCount:  currCount,
		})
	}
	for i := 1; i < len(frames); i++ {
		f := frames[i]
		if f.PlayerIndex == currTarget && f.TimeSecs-currEnd <= minGap {
			currEnd = f.TimeSecs
			currCount++
			continue
		}
		flush()
		currTarget = f.PlayerIndex
		currStart = f.TimeSecs
		currEnd = f.TimeSecs
		currCount = 1
	}
	flush()
	return periods
}

// ============================================================
// 5. Bomb plant: find planter's position at plant_complete game event
// ============================================================

func detectBombPlant(a *analysis.RoundAnalysis, players []PlayerInfoHeader) *analysis.BombPlantInfo {
	usernameIdx := make(map[string]int, len(players))
	for i, p := range players {
		usernameIdx[p.Username] = i
	}
	var plantT float32 = -1
	var planterIdx int = -1
	var planterUser string
	for _, ge := range a.GameEvents {
		if ge.Type != "plant_complete" {
			continue
		}
		// Text: "<username> planted the defuser"
		idx := strings.Index(ge.Text, " planted ")
		if idx <= 0 {
			continue
		}
		user := ge.Text[:idx]
		if pi, ok := usernameIdx[user]; ok {
			plantT = ge.TimeSecs
			planterIdx = pi
			planterUser = user
			break
		}
	}
	if planterIdx < 0 {
		return nil
	}
	// Find planter's position closest to plant time.
	for _, pt := range a.Players {
		if pt.PlayerIndex != planterIdx {
			continue
		}
		var bestDt float32 = 5
		var bestX, bestY, bestZ float32
		found := false
		for _, f := range pt.Frames {
			if f.IsCamera || f.TimeSecs == 0 {
				continue
			}
			dt := f.TimeSecs - plantT
			if dt < 0 {
				dt = -dt
			}
			if dt < bestDt {
				bestDt = dt
				bestX, bestY, bestZ = f.X, f.Y, f.Z
				found = true
			}
		}
		if !found {
			return nil
		}
		return &analysis.BombPlantInfo{
			PlanterIndex: planterIdx,
			Username:     planterUser,
			TimeSecs:     plantT,
			X:            bestX,
			Y:            bestY,
			Z:            bestZ,
		}
	}
	return nil
}

// ============================================================
// 6. Bomb site classification: from defender spawn metadata + Z-clusters
// ============================================================

func classifyBombSite(a *analysis.RoundAnalysis, players []PlayerInfoHeader) *analysis.BombSiteInfo {
	// Defenders all share the same spawn string in the header. Use that as the site label.
	for _, p := range players {
		if !p.IsAttack && p.Spawn != "" {
			site := &analysis.BombSiteInfo{
				Description: p.Spawn,
			}
			// Floor prefix: "1F", "2F", "3F", "B" (basement), "EXT"
			for _, prefix := range []string{"3F", "2F", "1F", "B ", "EXT"} {
				if strings.HasPrefix(p.Spawn, prefix) {
					site.Floor = strings.TrimSpace(prefix)
					break
				}
			}
			// Compute defender position center (mean of Z = floor reference).
			var sx, sy, sz float64
			var n float64
			for _, pt := range a.Players {
				if pt.PlayerIndex >= len(players) || players[pt.PlayerIndex].IsAttack {
					continue
				}
				for _, f := range pt.Frames {
					if f.IsCamera || f.TimeSecs > 30 { // sample only prep phase
						continue
					}
					sx += float64(f.X)
					sy += float64(f.Y)
					sz += float64(f.Z)
					n++
				}
			}
			if n > 0 {
				site.CenterX = float32(sx / n)
				site.CenterY = float32(sy / n)
				site.CenterZ = float32(sz / n)
			}
			return site
		}
	}
	return nil
}

// ============================================================
// 7. Round outcome: WinningTeam + WinCondition derived from events
// ============================================================

func computeRoundOutcome(a *analysis.RoundAnalysis, header HeaderInfo) *analysis.RoundOutcome {
	out := &analysis.RoundOutcome{WinningTeam: -1}

	// Tally deaths per team from kill events.
	atkDead, defDead := 0, 0
	deadSet := make(map[string]bool)
	for _, ge := range a.GameEvents {
		if ge.Type != "kill" {
			continue
		}
		parts := strings.SplitN(ge.Text, " killed ", 2)
		if len(parts) != 2 {
			continue
		}
		victim := parts[1]
		if deadSet[victim] {
			continue
		}
		deadSet[victim] = true
		for _, p := range header.Players {
			if p.Username != victim {
				continue
			}
			if p.IsAttack {
				atkDead++
			} else {
				defDead++
			}
			break
		}
	}
	out.AttackersDead = atkDead
	out.DefendersDead = defDead

	for _, ge := range a.GameEvents {
		switch ge.Type {
		case "plant_complete":
			out.Planted = true
		case "defuse_complete":
			out.Defused = true
		}
	}

	// WinningTeam from header.Teams
	for i, t := range header.Teams {
		if t.Won {
			out.WinningTeam = i
			out.WinningRole = t.Role
			break
		}
	}

	// Win condition heuristic.
	switch {
	case out.Defused:
		out.WinCondition = "DefusedBomb"
	case out.Planted && atkDead < 5 && defDead == 5:
		out.WinCondition = "PlantDetonation" // bomb went off
	case out.Planted && defDead == 0:
		// Defenders won despite plant — must have defused
		out.WinCondition = "DisabledDefuser"
	case atkDead == 5 || defDead == 5:
		out.WinCondition = "KilledOpponents"
	default:
		out.WinCondition = "Time"
	}
	return out
}

// ============================================================
// 8. Real per-slot loadout metadata from AmmoUpdates
// ============================================================
//
// AmmoUpdates carry deterministic slot identification via Hash2 (the gear-hash field):
//
//   Hash2 = 0x00000000  → primary weapon (ammo pool shared with weapon mag)
//   Hash2 = 0x29C80A40  → secondary weapon
//   Hash2 = 0xAA4BBC34  → throwable / grenade slot
//   Hash2 = 0x653E26DD  → operator-specific gadget
//
// Hash2 values were reverse-engineered from R06's ammo flow: each player has 1-4
// distinct (Hash1, Hash2) pairs. Hash1 is constant per property (0x29C80A40 = "available"
// counter; 0x3E6D5B6D = "remaining-of-a-different-counter"). Hash2 distinguishes slots.
//
// We DO NOT infer weapon names from operator templates — when the gameID isn't in
// gameItemNames, we leave the hex string as-is and surface the slot metadata so the
// consumer knows what the slot actually IS without us guessing what's IN it.

const (
	hash2Primary   uint32 = 0x00000000
	hash2Secondary uint32 = 0x29C80A40
	hash2Grenade   uint32 = 0xAA4BBC34
	hash2OpGadget  uint32 = 0x653E26DD
)

func slotTypeFromHash2(h2 uint32) string {
	switch h2 {
	case hash2Primary:
		return "primary"
	case hash2Secondary:
		return "secondary"
	case hash2Grenade:
		return "grenade"
	case hash2OpGadget:
		return "op_gadget"
	default:
		return ""
	}
}

func resolveSessionWeaponIDs(a *analysis.RoundAnalysis, players []PlayerInfoHeader) {
	// Build per-player slot summary from real ammo updates.
	// Each (PlayerIndex, Hash2) pair describes one loadout slot. Track:
	//   - shotCount: number of times we observed an ammo decrease (≈ shots fired)
	//   - maxCap: highest "Capacity" value (slot's full ammo pool)
	//   - prevAvailable: previous "Available" reading to detect decreases
	type slotData struct {
		shots    int
		maxCap   uint32
		lastAvail uint32
	}
	perPlayer := make(map[int]map[uint32]*slotData)
	for _, au := range a.LibraryAmmoUpdates {
		if au.PlayerIndex < 0 {
			continue
		}
		if perPlayer[au.PlayerIndex] == nil {
			perPlayer[au.PlayerIndex] = make(map[uint32]*slotData)
		}
		s, ok := perPlayer[au.PlayerIndex][au.Hash2]
		if !ok {
			s = &slotData{lastAvail: au.Available}
			perPlayer[au.PlayerIndex][au.Hash2] = s
		}
		// Increment shot count whenever Available decreases (indicates ammo consumed).
		if au.Available < s.lastAvail {
			diff := s.lastAvail - au.Available
			s.shots += int(diff)
		}
		s.lastAvail = au.Available
		if au.Capacity > s.maxCap {
			s.maxCap = au.Capacity
		}
	}

	// Attach slot metadata to loadout items based on Hash2 → slot type:
	//   primary weapon  ← Hash2 == 0x00000000
	//   secondary weapon← Hash2 == 0x29C80A40
	//   grenade slot    ← Hash2 == 0xAA4BBC34   (we map this to SecondaryGadget if it's a throwable)
	//   op gadget       ← Hash2 == 0x653E26DD   (PrimaryGadget for many ops)
	for i := range a.Loadouts {
		lo := &a.Loadouts[i]
		slots, ok := perPlayer[lo.PlayerIndex]
		if !ok {
			continue
		}
		if s, ok := slots[hash2Primary]; ok {
			lo.PrimaryWeapon.SlotType = "primary"
			lo.PrimaryWeapon.MaxCap = s.maxCap
			lo.PrimaryWeapon.ShotCount = s.shots
		}
		if s, ok := slots[hash2Secondary]; ok {
			lo.SecondaryWeapon.SlotType = "secondary"
			lo.SecondaryWeapon.MaxCap = s.maxCap
			lo.SecondaryWeapon.ShotCount = s.shots
		}
		if s, ok := slots[hash2Grenade]; ok {
			// Throwable slot — typically secondary gadget for most ops.
			lo.SecondaryGadget.SlotType = "grenade"
			lo.SecondaryGadget.MaxCap = s.maxCap
			lo.SecondaryGadget.ShotCount = s.shots
		}
		if s, ok := slots[hash2OpGadget]; ok {
			// Operator-specific gadget — primary gadget slot.
			lo.PrimaryGadget.SlotType = "op_gadget"
			lo.PrimaryGadget.MaxCap = s.maxCap
			lo.PrimaryGadget.ShotCount = s.shots
		}
	}
}
