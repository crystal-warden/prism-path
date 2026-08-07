# Arty Z7-20 / PYNQ bring-up — days 6–7 quickstart

Everything above the board is already certified: same images, same protocol, spec → C →
RTL → AXI, zero divergence. This is the remaining physical checklist.

## One-time board setup

1. microSD (PYNQ-Z1 v3.1.1, flashed + verified 2026-08-06) into the Arty's underside slot.
2. **JP4 boot jumper → SD** (it was on JTAG for the day-5 probing).
3. Ethernet from the Arty to the LAN; micro-USB stays on the rig (power + serial console).
4. Power on. First boot takes ~1–2 min (filesystem resize). The DONE LED lights when the
   PYNQ base overlay configures; LD4/LD5 flash when Linux is up.
5. Find the board: check the router's DHCP table for hostname `pynq`, or watch the serial
   console (COM3 on the rig, 115200) for the address. Login: `xilinx` / `xilinx`.
6. Drop the GB10's SSH key on it:
   `ssh-copy-id xilinx@<board-ip>`   (password xilinx — change it while you're there)

## Deploy the overlay + runtime (from GB10)

```sh
# the bitstream pair, built 2026-08-06 on the rig:
scp figue@100.101.145.39:C:/Users/figue/prismpath-hw/vivado/build_overlay/ppt_overlay.bit \
    figue@100.101.145.39:C:/Users/figue/prismpath-hw/vivado/build_overlay/ppt_overlay.hwh \
    xilinx@<board-ip>:/home/xilinx/
scp pynq/ppt_pynq.py xilinx@<board-ip>:/home/xilinx/
./deploy.sh <flow.md> <board-ip>        # emits live.ppt + live.json on the board
ssh xilinx@<board-ip> "sudo python3 ppt_pynq.py ppt_overlay.bit live.ppt live.json"
```

Then start the Mac bridge pointed at the **board**:
```sh
python3 field_bridge.py --host <board-ip> --port 9317
```

The board console prints routed decisions with per-sample µs round-trips; edits deploy
with `./deploy.sh` and hot-reload mid-stream (`*** TABLE RELOADED …`).

## Verification bundle inputs to record on demo day

- sha256 of `ppt_overlay.bit` (must be identical across takes), sha256 of each `.ppt`
- `fabric_route_log.ndjson` from the board, plus the flow `.md` files + git diff
- OTS stamps over the artifact set
