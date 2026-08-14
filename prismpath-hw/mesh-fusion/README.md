# mesh-fusion: distributed Level M decision fusion over ESP-NOW

Three ESP32 nodes, each sensing one channel, converge on **one** fused Level M decision that every node
computes identically. Where [`../mesh/`](../mesh) moves a single policy across the fleet, this moves
**many sensor streams into one decidable decision**, and lets the fleet hot-swap the fusion rule that
produces it. It is the decision fusion counterpart to the coordinated policy swap (evidence #100).

## The nodes

One binary (`main/ppt_fusion_mesh.c`) runs on all three boards; each selects its role by matching its
own Wi-Fi MAC against the baked `ROLES[]` map:

| slot | node | sensor | pins | band |
|---|---|---|---|---|
| 0 | tof-A | VL53L0X rangefinder | I2C GPIO21/22 | 0 contact .. 3 far (closer is lower) |
| 1 | tof-B | VL53L0X rangefinder | I2C GPIO21/22 | same |
| 2 | arm | potentiometer | GPIO35 / ADC1_CH7 | 0 low .. 3 high (arming knob) |

The pot is on ADC1 on purpose: ADC2 is unavailable while Wi-Fi is up.

## How it fuses

Each node projects its raw reading to a 0..3 band in plain code, broadcasts `{slot, band}` over ESP-NOW
every 200 ms, and holds the latest band from all three slots (one sensed locally, two received). The
**decision** is the decidable part: a signed `.ppt` table (`gen_fusion_mesh.py` compiles a three field
Markdown flow over `tof_a`, `tof_b`, `arm`) evaluated by the byte exact interpreter every substrate
certifies. The winning edge is the posture, shown on the onboard LED (GPIO2) so all three light the
same: solid CRITICAL, blink WARN, off OK.

```
CRITICAL  when tof_a <= 1 and tof_b <= 1 and arm >= 2   (both rangefinders close AND armed)
WARN      on a single close sensor, or a lightly armed one
OK        otherwise
```

CRITICAL is a region **no single node reaches alone**: it needs both rangefinders and the knob together.

## Two pre-vetted rules, coordinated swap

Two fusion policies are baked, each tagged with a 32-bit FNV-1a id: **A** arms at knob band `>= 2`, **B**
tightens that to `>= 3`. Poking one node over USB with `R` makes it coordinator for a two-phase commit
(the same contract as `../mesh/`): PREPARE broadcasts the target table + id, each follower re-hashes it
and checks the id is on its baked allowlist `{A, B}` before staging and ACKing, COMMIT fires only on a
two-node quorum, and every node flips at its own `local_now + 120 ms`. (The FNV allowlist stands in for
an Ed25519 signature, the named follow-on.) Hold the sensors in an A-CRITICAL state and a swap to B
re-fuses the whole fleet to WARN without a sensor moving.

## Fail operational, not fail silent

A distributed decision should not behave like a series circuit, where one dropped node kills the whole
verdict. A slot the mesh has not heard within 1500 ms reads a **STALE sentinel band (8)** instead of
being removed, so the signed table keeps deciding on it as a first-class input:

- **Escalate on loss**: a rangefinder going dark *while the system is armed* (or while a live
  rangefinder is at contact) reads as a possible defeat and escalates to **TAMPER**. A dark sensor is a
  signal, not silence.
- **Degrade otherwise**: a node dark while the scene is quiet drops to **DEGRADED**, so a problem is
  flagged and the fleet keeps fusing whatever remains.
- Because each node decides on what *it* can still hear, disagreement between nodes **localizes the
  fault** (an isolated node reports DEGRADED) rather than blanking the fleet.

Two failure modes are exercised:

- **Node loss**: a node dies, the survivors escalate to TAMPER (if armed) or DEGRADED, keep fusing the
  remaining sensors, and recover when it returns.
- **Interference**: a UART digit `0`..`9` drops that many tens of percent of received verdicts (`X` sets
  a 99% blackout; the PREPARE/COMMIT control plane is never dropped). Fusion holds through ~50% loss;
  beyond that, slots age into the STALE sentinel and the posture degrades or escalates rather than going
  quiet, then recovers when loss clears.

## Build, flash, run

```
idf.py set-target esp32
python gen_fusion_mesh.py          # (re)bake main/fusion_mesh_table.h from the flows + node MACs
idf.py build
idf.py -p /dev/ttyUSB0 flash       # same binary to all three boards
idf.py -p /dev/ttyUSB1 flash
idf.py -p /dev/ttyUSB2 flash

python orchestrate_fusion.py --secs 18                 # watch the fleet fuse
python orchestrate_fusion.py --secs 16 --swap-at 8     # ... and coordinate a fusion-rule swap
```

Node roles are keyed to specific board MACs in `gen_fusion_mesh.py`; re-run `esptool read_mac` and edit
`ROLES` for a different set of boards.
