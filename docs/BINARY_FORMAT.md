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
Offset from pattern:
  -16..-13  Entity ref (u32 LE, F0-prefix for players)
   -8..-5   Packet size (u32 LE)
    0.. 3   Pattern [60 73 85 FE]
    4.. 5   Type field (u16 LE, bitfield)
    6+       Payload
```

**Type field bits**:
- Bit 7 of byte[0] (`& 0x80`): position data present (3× f32 XYZ at payload start)
- Type `0x0880`: drone view marker (no position data)
- `0x03xx` types: full quaternion in trail (4× f32 at +4 after XYZ)

**Position types** (with XYZ): `0x03B8`, `0x01B0`, `0x01B8`, `0x01C0`, `0x1Fxx`
**Property-only types** (no XYZ): `0x0440`, `0x0130`, `0x0420`, `0x0630`

### SPAWN Records

**Archetype**: `0xFE857361` (LE bytes: `61 73 85 FE`)

```
  -12..-9   Entity ref (u32 LE)
    0.. 3   Pattern [61 73 85 FE]
    8.. 9   Counter (u16 LE)
```

**Counter values**:
- 494: player entity assignment record
- 154: drone
- 146: gadget
- 130: barricade (confirmed with FC-UPDATE flag `0x1FE0`)
- 138: primary weapon
- 254: secondary weapon

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

12 records per player (1 operator + 2 weapons + gadgets + other items).

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

**DBNO marker**: `22 96 E2 29 7F` — appears within ±70 bytes of a kill indicator when the kill was a finish (DBNO → confirm).

### Kill TLV Hashes

After the kill indicator, TLV fields with these hashes:

| Hash | Meaning |
|------|---------|
| `0x70DE98C1` | Killer team index (u32: 1 or 2) |
| `0x700F19AC` | Target username (string) |
| `0x507B2E78` | Target team index (u32) |
| `0x4EA45BC3` | Headshot flag (byte: 0x01) |
| `0x65DD6CF8` | Weapon entity ref (u64) |
| `0x41B24805` | Cumulative kill count in round (u32) |
| `0x7F29E296` | DBNO marker (f32: 5.0 or 10.0) |
| `0xF32D7DF5` | DBNO finish flag (byte) |
| `0x56B4E07A` | DBNO knocker team (u32) |
| `0xD241FB6C` | DBNO finisher team (u32) |

## Health Property

**Hash**: `0x4171D3C3` (in post-80% region)

Record format: `[ref8 8B] [hash 4B] [value f32 4B]` = 16 bytes

Values: `0.0` (dead), `100.0` (full), intermediates = damage taken.

**Co-located properties** (same ref8 block):
| Hash | Meaning |
|------|---------|
| `0x848F67CF` | Time-related float |
| `0xF634093A` | Hit/tick counter |
| `0x475BB68B` | Damage rate (0.067=DoT, 0.133=bullets) |
| `0xC2D846F8` | Max health (0 or 100) |

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

## Other Patterns

| Pattern | Purpose |
|---------|---------|
| `22 07 94 9B DC` | Player data record |
| `22 A9 26 0B E4` | Attacker operator swap |
| `AF 98 99 CA` | Spawn point data |
| `59 34 E5 8B 04` | Match feedback (kill/DBNO/death) |
| `22 A9 C8 58 D9` | Defuser timer |
