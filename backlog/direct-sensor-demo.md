# Backlog: direct-attach sensor demo — BNO086 on the Arty, decisions on the LEDs

*The owner's cut of the demo (2026-08-06): wave the board and sensor as ONE object on
camera; no Mac in the loop at demo time — "prove no weird behind-the-scenes magic on
screen." The plan called this the week-2 flourish; week-1 gates all closed on day 1, so
it's in scope. The Mac-bridge path stays banked as the fallback — this is additive.*

## The assembly

- BNO086 (Qwiic) → jumper pigtail → **Pmod JA** on the Arty: 3.3V, GND, SDA, SCL.
  SparkFun board carries its own I2C pull-ups. Zip-tie / standoff the sensor to the Arty
  so the pair handles as one rigid object (the Day-2 lesson: the wiring must out-survive
  the shake).
- Power: micro-USB from a **USB power bank** → fully handheld shots. (Board is fine on
  USB power; JP5 on USB.)
- Ethernet stays attached only for the edit-to-silicon segment (deploy + hot reload);
  detach it for the wave-it-around segment.

## Overlay v2 changes (small, well-bounded)

1. **I2C path — reuse the Feb 2026 design's own BNO086 wiring** (found 2026-08-07 in
   `Crystal_Warden_Core.srcs/constrs_1/.../CrystalWarden_Constraints.xdc` on the rig —
   the owner had built exactly this before shelving it):

   | Pmod JA pin | signal | package pin |
   |---|---|---|
   | 1 | BNO086 RST (AXI GPIO 0) | Y18 |
   | 2 | BNO086 INT (AXI GPIO 1) | W18 |
   | 3 | I2C SDA (AXI IIC) | Y19 |
   | 4 | I2C SCL (AXI IIC) | W19 |
   | 5/6 | GND / 3.3V | — |

   Mirror the Feb architecture: **AXI IIC + AXI GPIO** cells on the same interconnect as
   ppt_0, external tri-state ports, this XDC verbatim. The GPIO reset line is the same
   hardware-reset discipline bridge v5 relies on — wire it, use it in the board-side init.
   (EMIO I2C remains the fallback if AXI IIC misbehaves; Linux sees /dev/i2c-N via the
   xilinx AXI IIC driver either way. Also check `ConnectivityCheck/` — the Jan 29 project —
   for the Feb bring-up's I2C smoke tests.)
2. **LEDs driven BY THE FABRIC** — the upgrade on the owner's idea: latch the last
   matched target index in ppt_axi and wire it straight to the Arty's LEDs
   (LD0-3 + RGB LD4/5). The severity light is then asserted by the same silicon that made
   the decision — no software in the display path at all. watch=green, sev3=amber-ish
   (LED pick), sev2=both, sev1=red RGB. ~15 lines of RTL + 6 XDC lines.
3. Rebuild via the existing build_overlay.tcl (add the XDC; everything else unchanged).

## Board-side software

- The Day-2 field bridge logic runs ON the PYNQ Linux instead of the Mac: same patched
  read loop (watchdog + staleness reset + 20 Hz), transport swapped from MCP2221A-HID to
  /dev/i2c-N (Blinka generic-Linux I2C, or fall back to smbus2 + the minimal SHTP accel
  read — we only consume the accelerometer). The adafruit resilience patch must be applied
  in the board's venv too — same one-line change, documented in the Mac rig memory.
- `ppt_pynq.py --sensor` mode: read accel → derive fields (identical constants to bridge
  v5) → MMIO write → evaluate. TCP server mode stays for the fallback topology.

## Why this strengthens the claims

- One object on screen = the no-cut take needs no trust anywhere: the only variable that
  moves is the Markdown file, visible on screen, and the LEDs answer from fabric.
- It demonstrates the hexagonal boundary ON one device: impure harness (I2C, Linux) on
  the PS, pure routing kernel in the PL — the Sentinel architecture in miniature.

## Risks / order of work

1. Bring up I2C-over-EMIO with the sensor on the bench FIRST (i2cdetect shows 0x4B) —
   this is the only genuinely new plumbing.
2. Blinka-on-PYNQ friction is possible; smbus2 fallback is scoped small (accel-only SHTP).
3. Do not touch the banked Mac-bridge demo until the direct path passes the same
   choreography (watch → sev3 → sev2 → sev1 → watch) on the LEDs.
