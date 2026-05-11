# R6 Siege .rec Binary Format Reference

## File Structure

`.rec` files use zstd compression. Modern replays (Y8S4+) use chunked compression
with multiple zstd frames. Older replays are a single zstd stream.

After decompression, the binary contains:

1. **Header magic** — version identifier and game metadata
2. **Player data** — triggered by pattern `22 07 94 9B DC` (one per player)
3. **Operator swap data** — pattern `22 A9 26 0B E4` (attacker swaps during prep)
4. **Spawn points** — pattern `AF 98 99 CA`
5. **Game state replication stream** — the bulk of the file

## Movement Packets

### FC-UPDATE (Position/Rotation)

**Archetype**: `0xFE857360` (LE bytes: `60 73 85 FE`)

```
Offset from pattern (i = first byte of pattern):
  -12..-9   Entity ref low 32b (u32 LE, F0-prefix for game entities)
   -8..-5   Entity ref high 32b — always 0 (the engine's u64 id is sparse)
   -4..-1   Packet size (u32 LE)
    0.. 3   Pattern [60 73 85 FE]
    4.. 5   Type field (u16 LE, bitfield)
   +6..+7   Echo of entity ref low 16b
    8+      Payload
```

> **NOTE**: an earlier revision of this doc placed the entity ref at
> `-16..-13` and the packet size at `-8..-5`. Those positions hold zero /
> arbitrary bytes; the real layout matches `dissect/movement.go`
> (`r.b[i-12:i-8]` for ref, `r.b[i-4:i]` for size).

**Type field bits**:
- Bit 7 of byte[0] (`& 0x80`): position data present (3× f32 XYZ at payload start)
- Type `0x0880`: drone view marker (no position data)
- `0x03xx` types: full quaternion in trail (4× f32 at +4 after XYZ)

**Position types** (with XYZ): `0x03B8`, `0x01B0`, `0x01B8`, `0x01C0`, `0x1Fxx`
**Property-only types** (no XYZ): `0x0440`, `0x0130`, `0x0420`, `0x0630`

### SPAWN Records

**Archetype**: `0xFE857361` (LE bytes: `61 73 85 FE`)

```
Offset from pattern (i = first byte of pattern):
  -12..-9   Entity ref low 32b (u32 LE)
   -8..-5   Entity ref high 32b — always 0
   -4..-1   Counter (u32 LE)
   +4..+7   Echo of entity ref low 32b
   +8..+11  Always 0
  +60..+63  hashA (u32 LE) — gadget/sub-type identifier
  +64..+67  hashB (u32 LE) — paired with hashA for some counter=146 entities
```

> **NOTE**: an earlier revision of this doc placed the counter at `+8..+9` as
> a `u16`. Those bytes are always zero (high 16 bits of the entity-ref echo);
> the real counter is the u32 at `-4..-1`, matching `dissect/movement.go`
> (`r.b[i-4:i]`). Counters use the full 32-bit width — values up to 494
> appear in normal replays, so a `u16` read happens to truncate the field.

**Counter values** observed across 79 Y11S1 replays (31 038 SPAWN records,
by descending population):

| Counter | Per-match avg | Mapped meaning | Source |
|--------:|--------------:|----------------|--------|
| `98`  | 54.7 | projectile / VFX (paired with `266`) | distribution analysis |
| `94`  | 30.6 | unknown — not classified | – |
| `142` | 44.5 | secondary gadget (impact, claymore, jammer, …) | `dissect.classifySpawnCounters` |
| `130` | 43.9 | barricade (door / window / hatch reinforcement) | `dissect.classifySpawnCounters` |
| `146` | 35.4 | deployed gadget | `dissect.classifySpawnCounters` |
| `138` | 33.8 | primary weapon (or Azami Kiba, by spawn hash) | `dissect.classifySpawnCounters` |
| `126` | 33.5 | Alibi Prisma — and other counter-126 carriers | `dissect.classifySpawnCounters` |
| `254` | 29.8 | secondary weapon | `dissect.classifySpawnCounters` |
| `122` | 22.2 | unknown — short hashA values (`0x0000XXXX`) suggest spawn-point indices | – |
| `266` | 20.0 | projectile / VFX phase 2 (same hashA as `98`) | distribution analysis |
| `154` | 15.1 | player-controlled drone | `dissect.classifySpawnCounters` |
| `494` | 10.0 | player entity (one per loadout slot) | `dissect.classifySpawnCounters` |
| `150` | 5.7  | deployable secondary equipment (shield, …) | `dissect.classifySpawnCounters` |
| `158`/`162`/`110`/`90` | <0.1 | rare — undecoded | – |

> **`__9A` vs `__16` family pattern** (counter=142): every gadget hash with
> the `9A` low byte is a *placed* utility (jammer, battery, canister, kiba);
> every hash with the `16` low byte is a *thrown* explosive (C4 =
> `0x2D1E3B16`, plus 7 unmapped `XXXX_XX16` siblings). The low byte appears
> to be a class tag in the underlying name hash — useful as a fallback
> classifier when the exact gadget is not yet identified.

### SPAWN Gadget Identification (+60 / +64 from archetype)

| Counter | hashA @+60 | hashB @+64 | Gadget |
|---------|------------|------------|--------|
| 142 | `0x2D1E3A9A` |  | Mute Jammer |
| 142 | `0x2D1AAB9A` |  | Frost Welcome Mat |
| 142 | `0xD2F8F39A` |  | Bandit Battery |
| 142 | `0xFC72B39A` |  | Goyo Canister |
| 142 | `0x2D1E3B16` |  | Nitro Cell |
| 146 | `0x133B519A` | `0x0CC9B9B2` | Thunderbird Kóna Station |
| 146 | `0x133B519A` | `0x4F01B6B2` | Melusi Banshee |
| 146 | `0x133B519A` | `0x2D1C4FB2` | Jäger ADS |
| 146 | `0x1CA56E9A` | `0x2D1DAE35` | Mira Black Mirror |
| 138 | `0x9B72AE9A` |  | Azami Kiba Barrier |
| 150 | `0x1CA56E9A` |  | Deployable Shield |
| 126 | hash @+56: `0x45324600` |  | Alibi Prisma |

Resolved gadget name is exposed as `entities[].spawnGadgetName` in the JSON output.

### Gadget Inventory Counts

Late-file inventory records carry per-gadget primary/secondary counts:

```
[0x22 marker] [hash u32 LE] [0x04 type byte] [count u32 LE]
```

| Hash | Field |
|------|-------|
| `0x4FBDD114` | Primary gadget count |
| `0x44186B66` | Secondary gadget count |

Entity attribution: scan backward up to 128 bytes for a `0x22` or `0x23` marker
followed by an F0-prefix uint32 — that's the WEAPON / GADGET entity ref (not
the player entity ref directly; resolve via library `Loadouts.Primary/.Secondary`
entity refs). Exposed as `analysis.gadgetInventory[]` in JSON output.

## Bone Data

### Head Bone (BMA)

**Magic**: `02 00 70 88 98 58` (6 bytes)

Found within large FC-UPDATE packets. Payload (36 bytes after magic):

```
[0:4]   headOffX (f32) — lean displacement
[4:8]   headOffY (f32) — nod displacement
[8:12]  headOffZ (f32) — stance displacement
[12:16] separator (always 1.0)
[16:20] aimQx (f32) — head aim quaternion X
[20:24] aimQy (f32)
[24:28] aimQz (f32)
[28:32] aimQw (f32)
[32:36] separator (always 1.0)
```

### Chest Bone (BMB)

**Magic**: `00 2C 36 14 9B` (5 bytes)

Same 36-byte payload layout as head bone but for chest.

### Bone Inventory

R6 replays persist **only head and chest** bone transforms — verified by
exhaustive shape-based scan across the binary: only BMA (`02 00 70 88 98 58`)
and BMB (`00 2C 36 14 9B`) match the 36-byte `[xyz][1.0][quat][1.0]` payload
shape. Other body parts (arms, legs, feet, hands) are not stored in replay
files; they are reconstructed at playback time via inverse kinematics from
head + chest + position state.

### Two Bone Extraction Implementations

| Aspect | `dissect/movement.go` (streaming) | `analysis/bone.go` (batch) |
|--------|-----------------------------------|----------------------------|
| Trigger | Inline after each FC-UPDATE packet | Post-hoc full-buffer pass |
| Attach to | The just-appended PositionUpdate | Nearest position frame by binary offset |
| Entity resolve | Implicit (last PU's entity) | Backward scan for `60 73 85 FE` → entity ref at `-12` |
| BMB window | 10 bytes after BMA Section A | Same: `[BMAstart+36, BMAstart+46]` |
| Per-binary scan cost | O(packets) | O(bytes) for BMA hits + O(500) backward per hit |
| Coverage on R06 (25 619 player frames) | n/a (library doesn't expose to analysis) | 87.6% per frame |

## Ammo Events

**Pattern**: `77 CA 96 DE` (4 bytes)

```
  -8..-5   Weapon entity ID (u32 LE, F0-prefix)
  -4..-1   Zero padding (00 00 00 00)
   0.. 3   Pattern [77 CA 96 DE]
   4+       TLV fields (repeating)
```

**TLV field format**: `[04] [value u32 LE] [22 or 23] [hash u32 LE]` (10 bytes each)

**Property hashes**:
| Hash | Meaning |
|------|---------|
| `0x29C80A40` | Current magazine ammo (decrements per shot) |
| `0x3E6D5B6D` | Loaded ammo (magazine + chambered round) |
| `0xAA4BBC34` | Reserve ammo pool |
| `0x0A44F556` | Small counter (init events) |
| `0x219E95DE` | Grand total (reserve + loaded) |
| `0x653E26DD` | Running total remaining |

## Weapon Init Blocks

**Pattern**: `5F 85 CC 85` (last 5% of binary)

Two sub-types:
- **Type A**: byte at +4 = `0x1A`, weapon EID at +9
- **Type B**: byte at +4 = `0x22` and +5 = `0x14`, weapon EID at +16

Weapon EIDs are F0-prefix, matching ammo events. Two team clusters: DEF at ~98.5%, ATK at ~99%.

## Equipment Loadout

16-byte records in the header area (first 25% of file):

```
[GameID u64 LE] [auxHash u32 LE] [category u32 LE]
```

Categories:
- `0x16` / `0x18`: operator (solo/ranked)
- `0x0A`: weapon
- `0x03`: gadget

### Slot auxHashes (CRC32 of slot name)

| auxHash (decimal) | auxHash (hex) | Slot |
|-------------------|---------------|------|
| `3268402276`      | `0xC2C7C124`  | PrimaryWeapon |
| `1696241262`      | `0x651572EE`  | MeleeWeapon (session-variable IDs) |
| `1893246388`      | `0x70DAB934`  | SecondaryWeapon (canonical IDs — preferred) |
| `2606078005`      | `0x9B559835`  | Reinforcement (defender wall reinforcement) |
| `2947831256`      | `0xAFB455D8`  | SecondaryGadget (universal throwable / utility) |
| `497232904`       | `0x1DA32C08`  | **OperatorGadget** (signature gadget — Bandit's SHOCK WIRE, etc.) |

Per-player loadout block ≈ 506 bytes; defender blocks come first, then attackers. The
`MeleeWeapon` slot stores session-variable weapon IDs (`0x38C8D6___` family) that change
per match. The `SecondaryWeapon` slot stores canonical hashes that resolve to weapon names
via `gameItemNames` — always prefer `SecondaryWeapon` over `MeleeWeapon`.

### Ammo Hash2 slot identifiers

The Hash2 field in `AmmoUpdate` records identifies which slot the update is for:

| Hash2 | Slot |
|-------|------|
| `0x00000000` | Primary weapon |
| `0x29C80A40` | Secondary weapon |
| `0xAA4BBC34` | Throwable / grenade |
| `0x653E26DD` | Operator-specific gadget |

## Timer Ticks

**Pattern**: `1F 07 EF C9 04 [seconds u32 LE]`

Countdown timer (seconds remaining). Prep phase: counts down ~44s. Action phase: counts down ~180s.

## Kill Events

**Kill indicator**: `22 D9 13 3C BA` (5 bytes)

```
+0         Attacker username length (1 byte)
+1..+N     Attacker username (ASCII)
+N+1..+N+15  Skip 15 bytes
+N+16      Target username length (1 byte)
+N+17..+M  Target username (ASCII)
+M+1..+M+56  Skip 56 bytes
+M+57      Headshot flag (0 or 1)
```

**DBNO marker**: `22 96 E2 29 7F` — appears within ±256 bytes of a kill indicator when the kill was a finish (DBNO → confirm). Window was widened from 70 to 256 bytes for Y11S1+ which inserts additional TLV fields between markers.

### Kill TLV Hashes

After the kill indicator, TLV fields with these hashes:

| Hash | Meaning |
|------|---------|
| `0xD13DA88D` | **Attacker team index + 1** (u32) — `1` for team 0, `2` for team 1 (decoded R06) |
| `0x3187B853` | **Victim team index + 1** (u32) (decoded R06) |
| `0x70DE98C1` | Killer team index (u32: 1 or 2) — duplicate of `0xD13DA88D` |
| `0x700F19AC` | Target username (string) |
| `0x507B2E78` | Target team index (u32) |
| `0x4EA45BC3` | **Headshot flag (u8: 0x01)** — verified across all R06 kills |
| `0x65DD6CF8` | **Canonical weapon hash for this kill** (u64) — consistent across kills with same weapon |
| `0x41B24805` | Cumulative kill count in round (u32) |
| `0x7F29E296` | DBNO marker (f32: 5.0 or 10.0) |
| `0xF32D7DF5` | DBNO finish flag (byte) |
| `0x56B4E07A` | DBNO knocker team (u32) |
| `0xD241FB6C` | DBNO finisher team (u32) |

### Extended Kill TLVs

Additional TLV fields. Present from Y9S2+ (one or two TLVs absent in Y9S1). Scanned in a 256-byte window around each kill marker. Each TLV: marker (`0x22` or `0x23`) + hash u32 LE + type byte + value. Type bytes: `0x01`=u8, `0x04`=u32, `0x08`=u64.

Distributions verified across **402 kills** from **85 replays** spanning Y9S1, Y9S2_Beta01, Y10S3_Alpha02, Y11S1_Alpha03.

| Hash | Type | Decoded Meaning |
|------|------|-----------------|
| `0x790009E3` | u64 | Reserved sentinel — **always `0xFFFFFFFFFFFFFFFF`** when present (Y9S2+); absent (zero) in Y9S1 |
| `0x8F0292B5` | u8  | Reserved — always `0` across all 402 kills |
| `0x5BC4BC84` | u32 | **Y11-introduced kill metadata** — pre-Y11 always `1`; in Y11S1 splits 61%/39% between `1`/`2`. Specific semantics undecoded — possible candidates: wallbang flag, DBNO-finish flag, marked-target kill, or new Y11 mechanic |
| `0x37BF3E90` | u32 | Always `1` — kill-type marker |
| `0xD13DA88D` | u32 | **AttackerTeam + 1** (`1`=team 0, `2`=team 1) |
| `0x3187B853` | u32 | **VictimTeam + 1** |
| `0x0B64ADA5` | u32 | Reserved — always `0` across all 402 kills |
| `0x65DD6CF8` | u64 | **Canonical weapon hash** — same value across all kills with the same weapon |
| `0x4EA45BC3` | u8  | **Headshot flag** — corroborates the byte-offset headshot bit |

#### Sub-stream Kill TLVs (PR #5 — 4 new) — decoded semantics

| Hash | Type | Field | Meaning |
|------|------|-------|---------|
| `0x6C463718` | u32 | `roundTimeMs` | ms since round start |
| `0xC9527BDD` | f32 | `killDamage` | damage of killing bullet / max-health, in `[0, 1]` |
| `0xFB9DBF08` | f32 | `killRange` | weapon-dependent range / falloff factor, in `[0, 1]` |
| `0xA5F688E7` | u32 | `hitZone` | body-part hit bucket — observed values `0..4` (head / torso / limb / extremity / unknown) |

#### Sub-stream Duplicate Records (PR #4)

Y11S1 emits each kill TWICE — once in the primary stream and once in a parallel
sub-stream that carries additional metadata. Instead of skipping the duplicate
(as older code did), the scanner now merges TLVs from the duplicate into the
first event by key `(type, attacker, target)`:

| Hash | Type | Field | Meaning |
|------|------|-------|---------|
| `0x2219EC10` | u8  | `substreamFlag` | `1` = this record was produced by the secondary sub-stream |
| `0xEDB81094` | u32 | `extraEnumA` | observed `0..4` |
| `0x694D0B82` | u32 | `extraEnumB` | observed `0..3` |
| `0xC470472F` | u32 | `extraEnumC` | observed `2..5` |

### Per-Entity TLV Catalogue (0x23 marker)

Beside the kill-record TLVs, the binary stream carries a large catalogue of
per-entity property updates encoded as
`0x23 [ref8] [hash u32 LE] [type] [value]`. The entity ref is the F0-prefix
id of the SPAWN entity (or a sub-entity that does not get its own SPAWN —
common for world-state and animation sub-objects).

Hashes that occurred more than 1 000 times across a 79-replay corpus, with
the value type observed and our best current interpretation. Items marked
**probable** match a clear value pattern but have not been cross-validated
against game behaviour; treat them as hints, not contracts.

| Hash | Type | Occurrences | Distinct entities | Probable meaning |
|------|------|------------:|------------------:|------------------|
| `0xA374F4B6` | u32 | 697 184 | 1 369 | Per-entity tick / sequence counter (values 0..249, monotone in time) — **probable** |
| `0x6C463718` | u32 | 337 182 | 79 (one per replay) | **Round timestamp ms** (also re-used as kill TLV `roundTimeMs`) |
| `0xA80080B0` | u8 | 76 146 | 3 294 | Boolean flag — active/inactive state — **probable** |
| `0xD373835C` | f32 | 68 591 | 942 | Animation lerp 0..1 — **probable** |
| `0x54E5D055` | f32 | 69 725 | 138 | Animation lerp 0..1 — **probable** |
| `0xCA9998AF` | u64 | 27 515 | 1 667 | Sentinel `0xFFFFFFFFFFFFFFFF` — points to SPAWN system |
| `0xC13FD73B` | u8 | 25 454 | 4 810 | Boolean flag — visibility / replication-side — **probable** |
| `0xC1406A0D` | f32 | 22 898 | 3 766 | Values cluster 88..110, sometimes 0 — possibly speed scalar or anim timer |
| `0x0AD3AA3E` | u64 | 14 317 | 2 850 | Entity ref (parent / owner) — **probable** |
| `0x6252FDFF` | u32 | 13 122 | 6 382 | Small enum 0/1/2 — **probable** state field |
| `0xC9EF071F` | u32 | 12 944 | 79 (one per replay) | Per-replay tick counter — **probable** server tick |
| `0x2477AC66` | u32 | 12 819 | 1 398 | Small enum 0..3 — **probable** |
| `0xEC0D4FF6` | f32 | 10 477 | 20 (one per 20/79 replays) | f32 0..1 lerp — candidates: defuser progress, drone deploy anim |
| `0xD48DDCA4` | u8 | 10 065 | 789 | Boolean flag — **probable** |
| `0xA436B096` | f32 | 9 557 | 73 | Animation lerp 0..1 — **probable** |
| `0x88BE9E0E` | u64 | 8 655 | 7 482 | "Session item id" — families `0x1F1E397...`, `0x516BC...` — session-scoped instance IDs |
| `0xAFB7ACBC` | u8 | 8 363 | 1 679 | Always `1` — sub-stream presence marker — **probable** |
| `0x804FDAEC` | u32 | 6 837 | 948 | Small counter — **uncertain** |
| `0xD55F88F8` | u8 | 6 508 | 1 001 | Boolean flag — **probable** |
| `0x78B46D4F` | u8 | 6 175 | 941 | Boolean flag — **probable** |
| `0x4E254E7C` | u64 | 26 | 21 | **Operator role-portrait id** — matches `roleImage` of player-header records — **probable** |

## Health Property

**Hash**: `0x4171D3C3` (in post-80% region)

Record format: `[ref8 8B] [hash 4B] [value f32 4B]` = 16 bytes

Values: `0.0` (dead), `100.0` (full), intermediates = damage taken.

**Co-located properties** (same ref8 block):
| Hash | Meaning |
|------|---------|
| `0x848F67CF` | Time-related float |
| `0xF634093A` | Hit/tick counter |
| `0x475BB68B` | Damage rate — **decoded as hit type** |
| `0xC2D846F8` | Max health (0 or 100) |

**Damage-rate → hit-type decoding** (exposed as `healthUpdate.hitType`):

| Damage rate value | Decoded `hitType` |
|-------------------|-------------------|
| `0.067` (±0.005) | `"dot"` — gas/poison/bleed tick |
| `0.133` (±0.005) | `"bullet"` — direct firearm hit |
| other | `""` — unknown / not applicable |

## Scoreboard

| Pattern | Field |
|---------|-------|
| `EC DA 4F 80` | Cumulative score (u32) |
| `1C D2 B1 9D` | Kill count (u32) |
| `4D 73 7F 9E` | Assist count (u32) |

Offset -18 from pattern: marker `0x23`; offset -17 to -14: 4-byte player ID.

## Camera Frames

**Signature**: `[0xa5b2f3a5] [0x01] [varies 4B] [0x02] [qx qy qz qw]`

Entity ID: scan forward after quaternion for archetype `0xFE857360`, entity ref at -12 from archetype.

## Game Actions

| Pattern (10 bytes) | Action |
|---|---|
| `46 00 00 00 00 00 00 00 04 35` | Reinforce complete |
| `50 00 00 00 00 00 00 00 04 3F` | Gadget deployed |

## Defuser Timer Ticks

**Pattern**: `22 A9 C8 58 D9` (defuser timer event)

Each occurrence is a frame of plant/defuse progress. The library now emits one `DefuserTick`
per call with state derived from `r.planted` and `r.defuserDisabling`:

| State | Condition |
|-------|-----------|
| `planting` | `!r.planted` |
| `disabling` | `r.planted && (r.defuserDisabling \|\| timer increased vs prev)` |
| `planted_idle` | `r.planted` and not disabling |

Tick fields: `timeInSeconds`, `time` (mm:ss), `rawValue` (current timer), `prevValue` (previous timer), `state`.

## FC-UPDATE Flag Fingerprints

The 2-byte type code at `patternStart + 4` doubles as a behavioural classifier
when accumulated across an entity's packet stream.

| Flag | Meaning |
|------|---------|
| `0x0280` | Grapple line projectile |
| `0x07C0` | Impact grenade (also appears in thrown set) |
| `0x1FC0` | Impact init (first-flag-only) |
| `0x0380` | Thrown projectile (one of three present) |
| `0x3FC0` | Thrown projectile (final flag) |
| `0x1FE0` | Barricade — confirms counter=130 entity |
| `0x0440` | Property-only packet — used for gadget fingerprinting |
| `0x03C0` | Pairs with 0x0440 size to discriminate Lesion vs Kaid |

**Projectile sub-type classifier**: if an entity's flag set contains
`{0x0380, 0x07C0, 0x3FC0}` → thrown projectile.
If only `0x0280` → grapple. If `{0x1FC0, 0x07C0}` → impact grenade.

**0x0440 packet-size discriminator** for Alibi / Lesion / Kaid:

| 0x0440 dominant size | `0x03C0` present | Frame count | Identified |
|----------------------|------------------|-------------|------------|
| 24 | — | > 200 | Alibi Prisma |
| 21 | yes | — | Lesion Gu Mine |
| 21 | no | — | Kaid Rtila Electroclaw |

## Other Patterns

| Pattern | Purpose |
|---------|---------|
| `22 07 94 9B DC` | Player data record |
| `22 A9 26 0B E4` | Attacker operator swap |
| `AF 98 99 CA` | Spawn point data |
| `59 34 E5 8B 04` | Match feedback (kill/DBNO/death) |
| `22 A9 C8 58 D9` | Defuser timer (per-frame tick) |

---

## Usage Recipes

### Reconstruct Exact World-Space Aim Per Frame
1. Read `frame.headQX/QY/QZ/QW` (head bone quat in body-local space)
2. Read `frame.qx/qy/qz/qw` (body quat from `0x03xx` packet) — or reconstruct
   from `frame.yawDeg / pitchDeg` using ZXY Euler if the body quat is zero
3. `head_world = body_quat × head_local_quat` (Hamilton product)
4. Extract yaw/pitch from `head_world` using the formulas in the bone section
5. Result: pixel-level aim direction accounting for lean / nod / crouch

### Build Per-Shot Bullet Direction Vector
1. Each `libraryShots[i]` carries `headQX/QY/QZ/QW` at the moment of fire
2. Compute `head_world` quat as above
3. Rotate the game's forward axis (e.g. `(0, 1, 0)`) by `head_world` →
   3D bullet direction vector from the shooter's eye

### Correlate Kill → Shot
1. Parse kill event → get attacker username + `timeSecs`
2. Find the attacker's last `libraryShots[i]` with `timeSecs <= killTime`
3. Shot carries `x/y/z` (shooter pos) + head quat (aim direction)
4. Victim's `playerTrack.frames[nearest_time].x/y/z` = victim pos at death
5. Result: full kill geometry — where the shot came from, which direction,
   where the victim was

### Geometrically Validate Headshot
1. Compute shooter's world-space head aim (as above)
2. Compute victim's head-world position:
   ```
   victimHead = victim.frames[t].xyz + rotate(victim.frame.headOffXYZ, victim.frame.bodyQuat)
   ```
3. Cast a ray from shooter eye along aim direction
4. If the ray intersects a sphere of radius ~0.15m around `victimHead` →
   geometric headshot
5. Cross-validate with `binaryFeedback[].headshotByte` (`0x4EA45BC3`)

### Track Entity Lifecycle (Drone / Gadget / Barricade)
1. Parse SPAWN record → entity ref + counter
2. Look up counter table to get type label
3. Look up `+60` (and `+64` for counter-146) hash for specific gadget name
4. Read every FC-UPDATE for that entity ref → full position history
5. `entityTrack.healthEvents` → HP timeline; HP=0 → destruction event
6. Final `entityTrack.spawnGadgetName` is the identified gadget

### Classify Hit Type per Health Event
1. `healthUpdate.damageRate` is the raw f32 from hash `0x475BB68B`
2. Decoded `healthUpdate.hitType`:
   - `"bullet"` (0.133 ±0.005) — direct firearm hit
   - `"dot"` (0.067 ±0.005) — gas/poison/bleed tick
   - `""` — unknown / no rate recorded
3. Lets you separate Smoke gas / Lesion mines / bleeding from direct shots

### Recover Recording Player POV
1. Camera Pass 4 (`0xa5b2f3a5` signature) attributes all camera frames to the
   player with the most position frames = the recording player
2. `analysis.recordingPlayer` is the resolved player index
3. `analysis.cameraFrames[]` gives exact look direction per tick — independent
   of body rotation, so use it for FOV-accurate replay playback

### Round Timeline (Elapsed from Tick Anchors)
1. Timer ticks: pattern `1F 07 EF C9 04 [seconds u32 LE]` (countdown)
2. Phase gap > 5 s between ticks = new phase (prep → action)
3. `elapsed = phaseStartCountdown - currentCountdown`
4. For events with `binOffset`: interpolate piecewise linearly between adjacent
   tick anchors to get `elapsed`. Fall back to `roundDuration - countdown` for
   events whose offsets are outside the tick range (Y11S1 health stream lives
   below the first tick anchor; see `AssignHealthTimes`)
