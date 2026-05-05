package dissect

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"

	"github.com/rs/zerolog/log"
)

type MatchUpdateType int

//go:generate stringer -type=MatchUpdateType
const (
	Kill MatchUpdateType = iota
	Death
	DefuserPlantStart
	DefuserPlantComplete
	DefuserDisableStart
	DefuserDisableComplete
	LocateObjective
	OperatorSwap
	Battleye
	PlayerLeave
	Other
	DBNO
)

type MatchUpdate struct {
	Type                   MatchUpdateType `json:"type"`
	Username               string          `json:"username,omitempty"`
	Target                 string          `json:"target,omitempty"`
	Headshot               *bool           `json:"headshot,omitempty"`
	Time                   string          `json:"time"`
	TimeInSeconds          float64         `json:"timeInSeconds"`
	Message                string          `json:"message,omitempty"`
	Operator               Operator        `json:"operator,omitempty"`
	DBNOBy                 string          `json:"dbnoBy,omitempty"`
	FinishedBy             string          `json:"finishedBy,omitempty"`
	usernameFromScoreboard string
}

func (r *Reader) isValidScoreboardCorrection(correctedKiller string, target string) bool {
	if correctedKiller == target || len(correctedKiller) == 0 {
		return false
	}
	killerIdx := r.PlayerIndexByUsername(correctedKiller)
	targetIdx := r.PlayerIndexByUsername(target)
	if killerIdx < 0 || targetIdx < 0 {
		return false
	}
	return r.Header.Players[killerIdx].TeamIndex != r.Header.Players[targetIdx].TeamIndex
}

func (i MatchUpdateType) MarshalJSON() (text []byte, err error) {
	return json.Marshal(stringerIntMarshal{
		Name: i.String(),
		ID:   int64(i),
	})
}

func (i *MatchUpdateType) UnmarshalJSON(data []byte) (err error) {
	var x stringerIntMarshal
	if err = json.Unmarshal(data, &x); err != nil {
		return
	}
	*i = MatchUpdateType(x.ID)
	return
}

var activity2 = []byte{0x00, 0x00, 0x00, 0x22, 0xe3, 0x09, 0x00, 0x79}
var killIndicator = []byte{0x22, 0xd9, 0x13, 0x3c, 0xba}

func readMatchFeedback(r *Reader) error {
	if r.Header.CodeVersion >= Y9S1Update3 {
		if err := r.Skip(38); err != nil {
			return err
		}
	} else if r.Header.CodeVersion >= Y9S1 {
		if err := r.Skip(9); err != nil {
			return err
		}
		valid, err := r.Int()
		if err != nil {
			return err
		}
		if valid != 4 {
			return errors.New("match feedback failed valid check")
		}
		if err := r.Skip(24); err != nil {
			return err
		}
	} else {
		if err := r.Skip(1); err != nil {
			return err
		}
		if err := r.Seek(activity2); err != nil {
			return err
		}
	}
	size, err := r.Int()
	if err != nil {
		return err
	}
	if size == 0 { // kill or an unknown indicator at start of match
		killTrace, err := r.Bytes(5)
		if err != nil {
			return err
		}
		if !bytes.Equal(killTrace, killIndicator) {
			log.Debug().Hex("killTrace", killTrace).Send()
			return nil
		}
		username, err := r.String()
		if err != nil {
			return err
		}
		empty := len(username) == 0
		if empty {
			log.Debug().Str("warn", "kill username empty").Send()
		}
		if err = r.Skip(15); err != nil {
			return err
		}
		target, err := r.String()
		if err != nil {
			return err
		}
		log.Debug().Str("target", target).Msg("kill target parsed")
		if empty {
			if len(target) > 0 {
				u := MatchUpdate{
					Type:          Death,
					Username:      target,
					Time:          r.timeRaw,
					TimeInSeconds: r.time,
				}
				r.MatchFeedback = append(r.MatchFeedback, u)
				log.Debug().Interface("match_update", u).Send()
				log.Debug().Msg("kill username empty because of death")
			}
			return nil
		}
		u := MatchUpdate{
			Type:          Kill,
			Username:      username,
			Target:        target,
			Time:          r.timeRaw,
			TimeInSeconds: r.time,
		}
		if err = r.Skip(56); err != nil {
			return err
		}
		headshot, err := r.Int()
		if err != nil {
			return err
		}
		headshotPtr := new(bool)
		if headshot == 1 {
			*headshotPtr = true
		}
		u.Headshot = headshotPtr
		isFinishOff := false
		savedOffset := r.offset
		if err = r.Skip(20); err == nil {
			dbnoIndicator, byteErr := r.Int()
			if byteErr == nil && dbnoIndicator == 1 {
				isFinishOff = true
			}
		}
		r.offset = savedOffset
		if !isFinishOff {
			if searchBuf, searchErr := r.Bytes(70); searchErr == nil {
				dbnoMarker := []byte{0x22, 0x96, 0xe2, 0x29, 0x7f}
				for j := 0; j <= len(searchBuf)-5; j++ {
					if bytes.Equal(searchBuf[j:j+5], dbnoMarker) {
						flagIdx := j + 15
						if flagIdx < len(searchBuf) && searchBuf[flagIdx] == 0x01 {
							isFinishOff = true
						}
						break
					}
				}
			}
			r.offset = savedOffset
		}
		if !isFinishOff && r.time == 0 && r.timeRaw != "" && r.Header.CodeVersion >= Y10S4 {
			isFinishOff = true
		}
		log.Debug().
			Str("killer", username).
			Str("target", target).
			Bool("headshot", headshot == 1).
			Bool("is_finish_off", isFinishOff).
			Msg("kill event parsed")
		killerIdx := r.PlayerIndexByUsername(u.Username)
		targetIdx := r.PlayerIndexByUsername(u.Target)
		if killerIdx >= 0 && targetIdx >= 0 {
			killerTeam := r.Header.Players[killerIdx].TeamIndex
			targetTeam := r.Header.Players[targetIdx].TeamIndex
			if killerTeam == targetTeam {
				log.Debug().
					Str("killer", u.Username).
					Str("target", u.Target).
					Int("team", killerTeam).
					Msg("kill filtered (same team)")
				return nil
			}
		}
		if isFinishOff {
			for i := len(r.MatchFeedback) - 1; i >= 0; i-- {
				val := r.MatchFeedback[i]
				if val.Type == Kill && val.Target == u.Target && val.DBNOBy != "" {
					return nil
				}
			}
			for i := len(r.MatchFeedback) - 1; i >= 0; i-- {
				val := &r.MatchFeedback[i]
				if (val.Type == Kill || val.Type == DBNO) && val.Target == u.Target {
					knocker := val.Username
					if val.Type == Kill {
						val.Type = DBNO
						log.Debug().
							Str("knocker", knocker).
							Str("target", u.Target).
							Msg("converted kill to DBNO")
					}
					u.DBNOBy = knocker
					u.Username = knocker
					if username != knocker {
						u.FinishedBy = username
					}
					log.Debug().
						Str("finisher", username).
						Str("knocker", knocker).
						Str("target", u.Target).
						Msg("DBNO finish-off: kill credited to knocker")
					break
				}
			}
			if u.DBNOBy == "" {
				dbnoEvent := MatchUpdate{
					Type:          DBNO,
					Username:      username,
					Target:        u.Target,
					Time:          u.Time,
					TimeInSeconds: u.TimeInSeconds,
				}
				r.MatchFeedback = append(r.MatchFeedback, dbnoEvent)
				u.DBNOBy = username
				log.Debug().
					Str("knocker", username).
					Str("target", u.Target).
					Msg("synthesized DBNO for finish-off")
			}
			if r.Header.CodeVersion < Y10S4 && len(r.lastKillerFromScoreboard) > 0 && r.lastKillerFromScoreboard != u.Username &&
				r.isValidScoreboardCorrection(r.lastKillerFromScoreboard, u.Target) {
				u.usernameFromScoreboard = r.lastKillerFromScoreboard
			}
			r.lastKillerFromScoreboard = ""
			r.MatchFeedback = append(r.MatchFeedback, u)
			log.Debug().Interface("match_update", u).Send()
			return nil
		}
		inOvertime := false
		defuserPlantTime := float64(-1)
		for i := len(r.MatchFeedback) - 1; i >= 0; i-- {
			val := r.MatchFeedback[i]
			if val.Type == DefuserPlantComplete {
				defuserPlantTime = val.TimeInSeconds
			}
			if u.TimeInSeconds > val.TimeInSeconds+5 {
				inOvertime = true
			}
			if val.Type != Kill && val.Type != Death && val.Type != DBNO {
				continue
			}
			if val.Target == u.Target || (val.Type == Death && val.Username == u.Target) {
				timeDiff := val.TimeInSeconds - u.TimeInSeconds
				if val.Type == Kill && val.DBNOBy == "" && timeDiff >= 0 && timeDiff <= 10 {
					r.MatchFeedback[i].Type = DBNO
					finisher := u.Username
					if u.Username != val.Username {
						u.FinishedBy = u.Username
					}
					u.DBNOBy = val.Username
					u.Username = val.Username
					log.Debug().
						Str("knocker", val.Username).
						Str("finisher", finisher).
						Str("target", u.Target).
						Float64("timeDiff", timeDiff).
						Msg("inferred DBNO from duplicate kill")
					break
				}
				sameKiller := val.Username == u.Username
				isPlantBoundaryKill := defuserPlantTime >= 0 && val.TimeInSeconds <= defuserPlantTime && val.TimeInSeconds >= defuserPlantTime-1
				if inOvertime {
					if !sameKiller {
						log.Debug().
							Str("killer", u.Username).
							Str("target", u.Target).
							Str("original_killer", val.Username).
							Float64("existing_time", val.TimeInSeconds).
							Float64("new_time", u.TimeInSeconds).
							Msg("overtime re-kill allowed (different killer)")
						break
					}
					if !isPlantBoundaryKill {
						log.Debug().
							Str("killer", u.Username).
							Str("target", u.Target).
							Float64("existing_time", val.TimeInSeconds).
							Float64("new_time", u.TimeInSeconds).
							Float64("defuser_plant_time", defuserPlantTime).
							Msg("overtime re-kill allowed (same killer, not plant-boundary)")
						break
					}
				}
				log.Debug().
					Str("killer", u.Username).
					Str("target", u.Target).
					Float64("existing_time", val.TimeInSeconds).
					Float64("new_time", u.TimeInSeconds).
					Bool("plant_boundary", isPlantBoundaryKill).
					Msg("duplicate kill filtered (target already dead)")
				return nil
			}
		}
		if r.Header.CodeVersion < Y10S4 && len(r.lastKillerFromScoreboard) > 0 && r.lastKillerFromScoreboard != username &&
			r.isValidScoreboardCorrection(r.lastKillerFromScoreboard, u.Target) {
			u.usernameFromScoreboard = r.lastKillerFromScoreboard
		}
		r.lastKillerFromScoreboard = ""
		r.MatchFeedback = append(r.MatchFeedback, u)
		log.Debug().Interface("match_update", u).Send()
		return nil
	}
	// TODO: Y9S1 may have removed or modified other match feedback options
	if r.Header.CodeVersion >= Y9S1 {
		return nil
	}
	b, err := r.Bytes(size)
	if err != nil {
		return err
	}
	msg := string(b)
	t := Other
	if strings.Contains(msg, "bombs") || strings.Contains(msg, "objective") {
		t = LocateObjective
	}
	if strings.Contains(msg, "BattlEye") {
		t = Battleye
	}
	if strings.Contains(msg, "left") {
		t = PlayerLeave
	}
	username := strings.Split(msg, " ")[0]
	if t == Other {
		username = ""
	} else {
		msg = ""
	}
	u := MatchUpdate{
		Type:          t,
		Username:      username,
		Target:        "",
		Time:          r.timeRaw,
		TimeInSeconds: r.time,
		Message:       msg,
	}
	r.MatchFeedback = append(r.MatchFeedback, u)
	log.Debug().Interface("match_update", u).Send()
	return nil
}
