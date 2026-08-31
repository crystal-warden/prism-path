# Field walk: governed ESP-NOW mesh under range, policy swap, partition, and interference

**Date:** 2026-08-30. **Duration:** 1827 s (about 30 minutes), one continuous run.
**Trail:** `trail-2026-08-30-field-walk.jsonl` (9187 records, 9069 fused verdicts), this directory.
**Firmware:** `main/ppt_fusion_mesh.c` (unmodified), three ESP32 nodes, ESP-NOW, WiFi channel 1.
**Logger:** `field_walk.py` reading the office node over serial, injecting controls, stamping position marks.

## Summary

Three ESP32 nodes running one signed Level M fusion genome were taken outdoors and walked apart while a
single tethered node (the office node) recorded the fused decision continuously. On real radios, in the
open, the governed mesh reproduced every property we had only shown as a single process software prototype:

- A signed policy hot swap commits across the fleet only on a real quorum, and refuses otherwise, with no
  split brain, measured at three separate ranges.
- A node that leaves radio range becomes a first class STALE input that the signed table escalates to
  DEGRADED. The mesh keeps deciding on the remaining quorum instead of going dark, and re absorbs the node
  automatically when it returns.
- Under injected packet loss the fused decision degrades gracefully and recovers: 50 percent loss is
  invisible, and only near total blackout forces DEGRADED, never silence and never a false healthy verdict.

Everything landed on one timestamped, replayable trail with position marks, the same discipline as the
signed t_ns decision trails from the bench demos.

## Setup

Three physical ESP32 boards, one binary, each self selecting its role by MAC:

| Node | Slot | Role in the walk | Wiring |
|---|---|---|---|
| tof-A (`...df:d5:90`) | 0 | **office**, tethered to the host, the recorded vantage | fixed indoors |
| tof-B (`...6a:bc`) | 1 | **door**, powered at the threshold on a battery | fixed at the threshold |
| arm (`...e0:38:00`) | 2 | **walker**, carried out on a mobile battery | mobile |

Each node senses one channel, broadcasts its band every 200 ms, hears the other two, and runs the same
baked signed fusion table over all three to compute one posture (OK, WARN, DEGRADED, TAMPER, CRITICAL). An
unheard slot older than 1.5 s reads a STALE sentinel (band 8) that the table escalates rather than blanks.
A fusion rule swap uses a two phase commit (PREPARE, then quorum of ACKs, then a timed atomic FLIP), and a
UART knob drops a set percentage of received frames to simulate interference.

Because ESP-NOW is single hop broadcast, the office node hears the door and the walker directly and fuses
what it hears. It does not relay, so the walker leaving the office range is the clean partition variable.

Honest note on sensing: the walker node's slot read a floating input (no sensor was wired for this run), so
its band sat at 0 while heard. The band value is not a measurement here. This run measured the radio and the
governance, for which the sensor content is irrelevant; the meaningful signal is present (band 0) versus
partitioned (STALE band 8).

## Results

### 1. Range and connectivity

| Position (owner estimate) | Approx. office distance | Walker link |
|---|---|---|
| Threshold | ~32 ft, through the structure wall | solid |
| Mid point | ~64 ft, through structure | telemetry solid, handshake marginal |
| Range edge | past the mid point | intermittent, flapping present/STALE |
| Far point | max range reached | steadily partitioned |

The through structure envelope matches the previously measured ~50 to 60 ft. A useful asymmetry appeared at
the mid point: the tiny 200 ms telemetry beacons kept arriving (the walker read live) while the larger policy
swap handshake could not complete a round trip. Small periodic state survives a marginal link that a large
one shot exchange does not.

### 2. Policy hot swap: commit only on quorum

Three swaps were fired at three ranges. The fusion rule flipped only when a real quorum of two of the other
two nodes acknowledged; every degraded case refused and left the fleet coherent on its current policy.

| Attempt | Walker position | ACKs | Outcome |
|---|---|---|---|
| Swap 1 | mid point (edge) | 1 of 2 (door only) | **ABORT**, stayed on policy A |
| Swap 1 retry | threshold (in range) | 2 of 2 (door + walker) | **COMMIT**, FLIP A to B, epoch 1 |
| Swap 2 | the range edge (partitioned) | 0 of 2 | **ABORT**, stayed on policy B |

The commit propagated across the radio to the walker and flipped the fusion rule with no re flash, and the
verdict stream never paused through the flip. The two aborts are the important half: at the range edge the
walker's ACK missed the 500 ms window, and under partition the whole handshake failed, and in both cases the
mesh conservatively kept a single coherent policy rather than risk some nodes on A and others on B. Only a
genuine quorum ever changes the fleet's rule.

### 3. Partition and fail operational behavior

Walking the walker out, its slot transitioned present (band 0, OK) to STALE (band 8, DEGRADED) at the range
edge. The longest continuous partition was 589 verdicts, about 118 s, at the far point. Throughout,
the door node stayed live and the office plus door held quorum, so the fused verdict sat at a steady
DEGRADED. The lost node localized the fault and escalated the posture; the mesh never went silent and never
reported a healthy collective it could not actually see.

### 4. Rejoin

Walking back in, the walker re entered range and the office re absorbed it automatically: the slot recovered
to live within the 1.5 s freshness window (15 of 15 readings live at the mid point on the return), verdict back
to OK, with zero operator intervention. Partition out and rejoin in are both automatic and both on the trail.

### 5. Interference: graceful degradation

With the walker back on a strong link at the door, the office reception drop knob was swept so the only
variable was injected loss:

| Injected drop | Walker STALE | Door STALE | Verdict |
|---|---|---|---|
| 0 percent (baseline) | 0 / 14 | 0 / 14 | OK |
| 50 percent | 0 / 26 | 0 / 26 | OK (fully tolerated) |
| 90 percent | 9 / 24 | 3 / 24 | OK and DEGRADED (onset) |
| 99 percent (blackout) | 26 / 26 | 22 / 26 | DEGRADED |
| 0 percent (cleared) | 3 / 30 | 6 / 30 | OK (recovered) |

Half the frames can be dropped with no visible effect: the 200 ms cadence inside the 1.5 s freshness window
absorbs it. As loss climbs to 90 percent the window starves and the verdict flaps. Under near total blackout
the mesh holds a steady DEGRADED (the office keeps its own reading and refuses to claim a healthy collective
it cannot hear), and it recovers to OK on its own when the interference clears.

## What this evidences

For the SABER technical volume this is the "governed, partition tolerant mesh" element and the Task 5 DDIL
robustness intent, demonstrated on physical radios rather than asserted from a single process self test:

- **Governance under partition.** The signed policy swap commits only on quorum and refuses otherwise, shown
  at in range, edge, and partitioned positions. No split brain.
- **Fail operational partition tolerance.** A dropped node becomes a STALE sentinel that escalates the
  verdict; the remaining quorum keeps deciding; rejoin is automatic.
- **Graceful degradation under interference**, with a measured tolerate then degrade then recover curve.

This upgrades those specific claims from "software verified prototype" to "measured on hardware in the
field." It is the on device signed table fusion and two phase quorum swap that ran here; it is a sibling of,
not identical to, the host side quorum or abstain prototype (`flow-studio/pipeline/quorum.py`), which remains
the abstain first model. Both are honest, and they are distinct mechanisms.

## Caveats

- **Single vantage.** Only the office node was recorded. Spatial diversity (a closer node holding the walker
  link after the office loses it) was not captured and needs a second recorded observer.
- **Distances are owner estimates**, not surveyed. RSSI was not emitted by the firmware; connectivity was
  measured by delivery and STALE transitions, not signal strength.
- **The walker slot was unsensed** (floating input); its band is not a measurement. Irrelevant to the radio
  and governance results, but stated for honesty.
- **Interference was injected at the receiver** (a UART drop knob at the office), a faithful model of a
  degraded link but not a real RF jammer.

## Reproduction

- Firmware: `main/ppt_fusion_mesh.c`, built and flashed with ESP-IDF 5.4 to three ESP32 boards on channel 1.
- Logger: `python3 field_walk.py --port /dev/ttyUSB0 --out trail.jsonl --ctl /tmp/mesh_ctl`
- Controls during the run: `echo swap|intf N|blackout|clearintf|mark <text>|quit > /tmp/mesh_ctl`
- Full timeline and every verdict, swap, partition, and interference window: `trail-2026-08-30-field-walk.jsonl`.

## Timeline (relative seconds)

```
+  50s  baseline, all three nodes on the desk
+ 729s  outside threshold, walker and door unit both present
+ 828s  at the mid point
+ 919s  SWAP1 ABORT at mid point (door 1/2, walker handshake missed)
+1049s  back at threshold, in range
+1088s  SWAP1 retry COMMIT (2/2), FLIP A to B epoch 1, decisions unbroken
+1151s  mid point, outbound
+1222s  the range edge, intermittent edge (walker flapping)
+1306s  walker steadily partitioned, firing SWAP2
+1382s  SWAP2 ABORT under partition (0/2), fleet stays on B
+1382s  the far point, max range
+1505s  mid point, inbound
+1530s  REJOIN confirmed, walker recovered to OK automatically
+1619s  interference sweep begins at the door
+1638s  interference cleared, mesh healthy
```
