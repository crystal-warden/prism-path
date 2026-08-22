# ESP-NOW mesh interference runbook

The real-RF counterpart to #107 (the native codec's modeled Gilbert-Elliott burst soak). We put the
three-node spiral mesh under real 2.4 GHz interference and measure the burst channel, the decision
tier's survival, and integrity. The claim we are after: **over real RF bursts the band tier still
carries the decision often enough, coherence degrades gracefully, and zero wrong symbols are ever
decoded** (ESP-NOW drops FCS-failed frames, so a wrong symbol would be a real defect).

## 0. Prep (do once, before the session)

- **Reflash B=1.** Interference wants per-frame loss granularity so a lost band frame is exactly one
  lost tick (clean burst run-lengths for the #107 comparison). The boards are currently on the B=5
  batch build. Force B=1:
  ```bash
  cd prismpath-hw/spiral-mesh
  unset BATCH_TICKS
  source ~/cwprojects/esp-idf/export.sh
  idf.py reconfigure && idf.py build          # reconfigure clears the cached BATCH_TICKS define
  for p in /dev/ttyUSB2 /dev/ttyUSB3 /dev/ttyUSB4; do idf.py -p $p flash; done
  ```
  (Optionally repeat the whole campaign at B=5 afterward to show batch-loss behavior; B=1 is the
  headline.)
- **Sanity:** `python3 referee_interference.py baseline 20` should read ~99% band delivery, 0 wrong,
  high coherence with no interference present.

## 1. The phases (~2 minutes each; run one command per phase)

Each phase: I start the capture, you perform the action, I stop and it writes `phase_<label>.json`.

| Phase | You do | Channel effect |
|---|---|---|
| `baseline` | nothing | clean reference |
| `microwave` | run the microwave (**mug of water inside, never empty; ESP boards OUTSIDE**), ~1 m away | wideband ~2.45 GHz **bursts** — the direct G-E analog |
| `hotspot` | box saturates the phone hotspot on **channel 1** (`./interference_wifi.sh` below) | co-channel Wi-Fi contention |
| `bowl` | invert the aluminum mixing bowl over **one** ESP | strong attenuation of one link (asymmetric mesh) |
| `hand` | cup a hand over one ESP's antenna, on/off every few seconds | short deep fades |
| `recovery` | remove all interference | confirms it returns to baseline |

```bash
python3 referee_interference.py microwave 120     # etc., one per phase
```

## 2. Read it out

```bash
python3 referee_interference.py --aggregate
```

Prints per-phase band %, refinement %, max/mean burst length, wrong-symbol count, and coherence,
then the cross-phase **integrity verdict** (must be 0 wrong symbols — the mesh's "#107 on real RF").
The `burst_runlength_hist` in each `phase_*.json` is the measured burst channel to put beside #107's
modeled Gilbert-Elliott burst lengths.

## Notes

- Each frame carries the **sender's** tick, so losses are exact (sent-but-not-received per directed
  link, 6 links total). Boundary runs at the window edges are negligible over 2 minutes.
- The band tier (class 1) rides every tick; refinement (class 2) every 5th. They are reported
  separately — the point is the decision-lossless band tier surviving where the magnitude refinement
  does not.
- Safety: the microwave is the interferer, not a fixture — nothing of ours goes inside it, and it
  never runs empty. The bowl/foil/hand are all outside-the-oven attenuators.
