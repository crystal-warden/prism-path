# Walker → mesh → FPGA → LED: runbook + overnight results

Built + tested 2026-08-21 night. **The whole chain is proven end to end** — a carried BNO086+ESP32
walker broadcasts its motion over ESP-NOW; a fixed mesh node hears it; gx10 bridges the band to the
FPGA; the fabric interpreter decides and lights the RGB LED. No wire from the sensor to the FPGA.

## The chain

```
BNO086 --I2C--> ESP32 (walker, ttyUSB3 for flashing; battery when carried)
   read linear accel -> magnitude -> band 0..4 -> Facet frame [class=1,tick,band] -> ESP-NOW broadcast
        |  (wireless)
        v
fixed mesh node (ttyUSB2 = range_a, runs mesh_node.c) hears it, prints:  R 2 c1 t<tick> v<band>
        |  (USB serial to gx10)
        v
gx10  mesh_bridge.py  ->  band on stdout  ->  ssh -J ... xilinx@10.10.10.2  ->  run_led.sh
        |
        v
board  led_from_band.py: quiesce auto, load datapath overlay (PS mode), for each band:
   band -> pot-field value -> FPGA interpreter evaluate -> decision node -> RGB LED color
```

## What was verified overnight

- **Walker firmware** (`walker-fw/`): BNO086 up via the CEVA SH-2 driver over the `i2c_master` driver
  (rides the BNO08x clock stretching), INT-gated reads (GPIO25), linear-accel streaming, ESP-NOW
  broadcast of band frames. `sh2_open OK`, `enable OK`, `TX tick=N band=B`.
- **Wireless hop**: a fixed node prints `R 2 c1 v0` (walker = role 2) and fuses it into the mesh
  posture (`P .. route=watch/ok`). The walker's motion is a live k=3 fusion input.
- **gx10 bridge** (`mesh_bridge.py`): pulls `R 2 c1 v<band>` off the node, emits the band.
- **Full chain (resting walker)**: `band=0 -> node=3(low) -> led=0x02` (GREEN). Proven.
- **Band-change sweep** (`sim_motion.py` standing in for shaking): 0-1 → green(low), 2 → blue(mid),
  3-4 → red(high), up and back down, all correct. The FPGA decides every band; the LED tracks.

**Only remaining check (needs hands): shake the walker and watch the LED go green→blue→red live.**
The sensor→band half was already proven with a standalone shake earlier (band flipped to `move` at
~0.64 m/s²); the sim proves everything downstream. So the shake test is a formality.

## Band → color (via the signed demo_input interpreter)

| walker band | motion | pot-field | FPGA decision | LED |
|---|---|---|---|---|
| 0, 1 | still / light | 200, 500 | low | green (0x02) |
| 2 | move | 1000 | mid | blue (0x04) |
| 3, 4 | brisk / vigorous | 1800, 2600 | high | red (0x01) |

The band→pot mapping (`BAND_POT` in `led_from_band.py`) and the accel→band thresholds (`band_of` in
`walker.c`) are the two knobs to calibrate against real walking/gestures in the morning.

## Run it (morning)

```bash
cd ~/cwprojects/prismpath-hw/walker-demo
./run_walker_demo.sh              # reads ttyUSB2 (range_a) by default; Ctrl-C to stop
# then SHAKE the walker: LED should go green -> blue -> red
```

Board files are already deployed (`/home/xilinx/led_from_band.py`, `/home/xilinx/run_led.sh`,
`demo_input.ppt/json`). The board is currently left in its **armed auto (pot) demo**; starting the
chain quiesces that and takes over the LED.

## Ports / MACs

- walker = ttyUSB3, MAC `68:09:47:e0:38:00` = mesh role 2 (fills the `pot` fusion slot with real motion)
- fixed nodes: ttyUSB2 = range_a (role 0), the node the bridge reads; the other = range_b (role 1)
- ttyUSB0/1 = the FPGA's Digilent UART (leave alone)

## Gotchas learned (so we don't relive them)

1. **BNO086 needs a fresh power-cycle** (unplug/replug USB) if it wedges — an ESP32 reset does NOT
   power it down (it runs off the ESP32's 3V3). Symptom: all I2C transfers time out.
2. **Clock stretching**: use the `i2c_master` driver, not legacy `driver/i2c.h`. Legacy = every data
   transfer times out (the Mac Blinka `pass` was the same issue from the other side).
3. **INT gating is load-bearing**: read only when GPIO25 is low. Reading without data-ready wedges the
   bus. Secure that wire.
4. **`pkill -f mesh_bridge`** will self-kill any command that also names `mesh_bridge.py` (exit 144).
   Kill by PID or a pattern that can't match the running command.
5. Flash the walker only on its exact port: `idf.py -p /dev/ttyUSB3 flash` — never auto-detect with
   the mesh nodes plugged in.

---

# PL-native UART path (no processor in the FPGA decode)

Built + synthesized 2026-08-22. The checkpoint above keeps the PS in the courier role (gx10 relays
the band, `led_from_band.py` evaluates over AXI). This variant removes the processor from the decode
path entirely: a byte arrives on a Pmod pin, a UART receiver **in the fabric** recovers it, and the
Level M interpreter decides on it and lights the LED, all in the PL. The PS only arms the loop.

```
walker (BNO086+ESP32) --ESP-NOW band frame--> bridge ESP32 (bridge-fw)
    decode band in the MCU -> one byte (115200 8N1) on UART1 TX (GPIO17)
        |  (a single wire + GND)
        v
Arty Z7-20 Pmod JA1 (Y18) -> uart_rx.sv IN THE FABRIC -> field = byte<<4
        -> ppt_interp (Level M) -> per-node color LUT -> RGB LED   [all in the PL]
```

## Artifacts

- `../rtl/uart_rx.sv` - 115200 8N1 receiver in the PL (2FF sync, samples bit centres, LSB first).
- `../rtl/ppt_datapath_uart.sv` - the datapath with the field source switched from the XADC pot to the
  UART byte. Once a byte lands the field follows it (`uart_seen`); until then it follows the pot, so the
  knob still works standalone. `POT_NOW` (0x2C) reflects the actual field either way.
- `../vivado/build_overlay_uart.tcl` + `../vivado/uart.xdc` - build the overlay; `uart_rx_pin` on JA1 (Y18).
- `../vivado/build_overlay_uart/ppt_datapath_uart.bit` (+ `.hwh`) - **synthesized 50 MHz, WNS +1.598 ns,
  WHS +0.046 ns, 0 failing endpoints** (1818 LUTs, 0.5 BRAM). Separate file from the checkpoint bit.
- `bridge-fw/` - the ESP-NOW -> UART courier firmware (ESP-IDF, esp32). Decodes the walker's zeck band
  frame and sends `BAND_BYTE[band]` on UART1 TX. Decoder round-trip verified 40/40 against the walker's
  encoder.
- `arm_uart_auto.py` - board-side: load the overlay, load the policy + colors, arm auto mode.
- `uart_send_band.py` - a standalone byte source (any USB-serial) to prove the fabric decode WITHOUT
  the mesh.

## band -> byte -> field -> color

`BAND_BYTE = [13, 31, 63, 113, 163]` (= `round(BAND_POT/16)`); the fabric computes `field = byte<<4`,
so it lands in the same policy buckets the pot demo was certified on (cuts at `>=1631` high, `>=665` mid):

| band | byte | field (byte<<4) | FPGA decision | LED |
|---|---|---|---|---|
| 0, 1 | 0x0d, 0x1f | 208, 496 | low | green (0x02) |
| 2 | 0x3f | 1008 | mid | blue (0x04) |
| 3, 4 | 0x71, 0xa3 | 1808, 2608 | high | red (0x01) |

## Bring-up (morning, needs hands)

**Stage 0 - prove the fabric decode first, no mesh, no bridge.** Wire any USB-serial TX to JA1 (Y18)
and a JA GND pin. On the board, deploy + arm:

```bash
# on the dev box: push the new bit + the arm script to the board
scp ../vivado/build_overlay_uart/ppt_datapath_uart.bit  xilinx@10.10.10.2:/home/xilinx/
scp arm_uart_auto.py                                     xilinx@10.10.10.2:/home/xilinx/
# on the board:
sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
              source /etc/profile.d/boardname.sh; python3 /home/xilinx/arm_uart_auto.py'
# on the dev box (or wherever the USB-serial is):
python3 uart_send_band.py /dev/ttyUSB0 sweep     # LED should ramp green -> blue -> red
```

If the LED tracks the sweep, **the PL-native decode works** and the arm script's `field=` readback
should match the bytes sent. If it does not, **revert to the checkpoint** (load `ppt_datapath.bit`
and run the proven `led_from_band.py` chain above) - the checkpoint bit is untouched.

**Stage 1 - add the bridge.** Flash `bridge-fw/` to the second ESP32
(`idf.py set-target esp32 && idf.py -p /dev/ttyUSBx flash monitor`). Wire its UART1 TX (GPIO17) to
JA1 (Y18) and its GND to a JA GND pin. Power the walker. Shake it: the walker broadcasts bands, the
bridge forwards the byte, the fabric lights the LED. The bridge's monitor prints
`band=B -> UART 0x.. (field=..)` on each change.

## Gotchas for this path

1. **Same WiFi channel.** The bridge pins channel 1 (`WIFI_CH`); the walker uses the default (1). If
   you changed either, make them match or ESP-NOW frames will not arrive.
2. **Common ground.** The ESP32 and the Arty must share GND, or the UART line floats.
3. **JA1 is Y18** (`uart_rx.sv` idles high; ESP32 UART TX idles high, direct 3V3, no level shift).
4. **The checkpoint is the fallback, always.** `ppt_datapath_uart.bit` is a distinct file;
   `ppt_datapath.bit` (the certified pot demo) is never overwritten by this build.

---

# Native Facet decode (the FABRIC decodes the walker's wire)

The byte-mode path above still decodes the zeck frame in the bridge MCU and sends a pre-cooked field
byte. This tier removes even that: the bridge forwards the walker's **raw zeck frame bytes**, and the
frame is decoded **in the PL** by the same shift-register codec that closes Phase C2. No processor
touches the wire.

```
walker (BNO086+ESP32) --ESP-NOW zeck frame [class,tick,band]--> bridge ESP32 (bridge-fw, FORWARD_RAW_FRAME=1)
    forwards the RAW frame bytes on UART1 TX (GPIO17), no decode
        |  (one wire + GND)
        v
Arty Z7-20 Pmod JA1 (Y18) -> uart_rx.sv -> zeck_frame_rx.sv (decodes the frame, gap-delimited)
    -> band -> BAND_POT LUT -> field -> ppt_interp (Level M) -> per-node color -> RGB LED   [all in the PL]
```

## Artifacts

- `../rtl/zeck_dec.sv` - the Phase C2 decoder (measured on silicon; see `codec-bench/rtl-codec.md`).
- `../rtl/zeck_frame_rx.sv` - feeds uart_rx bytes bit-serially into zeck_dec, counts the three codes
  `[class+1, tick+1, band+1]`, emits band. Frames self-delimit by the idle gap between the walker's
  bursts (`GAP_TICKS`, ~1ms), so no framing protocol is needed. cocotb: 10/10 walker frames -> band.
- `../rtl/ppt_datapath_zeck.sv` (+ `_top.v`) - the datapath with the field source switched to the
  fabric-decoded band (mapped through the checkpoint's `BAND_POT` LUT). Until a frame lands the field
  follows the pot, so the knob still works standalone.
- `../vivado/build_overlay_zeck_demo.tcl` -> `ppt_datapath_zeck.bit` (+ `.hwh`); reuses `uart.xdc` (JA1).
- `bridge-fw/` with `FORWARD_RAW_FRAME 1` (default) - the MCU is now a dumb courier.

## Bring-up (morning, needs hands)

```bash
# on the dev box: push the overlay + arm script to the board
scp ../vivado/build_overlay_zeck_demo/ppt_datapath_zeck.bit ../vivado/build_overlay_zeck_demo/ppt_datapath_zeck.hwh \
    xilinx@10.10.10.2:/home/xilinx/
scp arm_uart_auto.py xilinx@10.10.10.2:/home/xilinx/
# on the board: arm auto (defaults to the zeck overlay)
sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh; \
              source /etc/profile.d/boardname.sh; python3 /home/xilinx/arm_uart_auto.py'
# flash the bridge (FORWARD_RAW_FRAME=1), wire UART1 TX (GPIO17)->JA1 (Y18) + shared GND, power the walker.
# Shake it: the fabric decodes each frame and lights the LED. arm's POT_NOW readback shows the field.
```

The band -> field -> color mapping is unchanged from the byte-mode table above (band 0-1 green,
2 blue, 3-4 red). The tier ladder for fallback: **native fabric decode (`ppt_datapath_zeck`)** ->
byte-mode MCU decode (`ppt_datapath_uart`) -> the original mesh + `led_from_band.py` checkpoint ->
the armed pot demo (`ppt_datapath.bit`). Each lower tier is a distinct bitstream and stays intact.
