#!/bin/bash
# The walker -> mesh -> FPGA -> LED demo, one command. Reads a FIXED mesh node's serial, extracts
# the carried walker's motion band (heard over ESP-NOW), and pipes it to the board daemon, which
# feeds each band to the FPGA interpreter and lights the RGB LED from the decision. Nothing is wired
# from the walker to the FPGA - the sensor is wireless. Ctrl-C to stop; the board falls back to its
# armed auto (pot) demo on the next dp_load.
#
#   ./run_walker_demo.sh [/dev/ttyUSB2]
#
# Prereqs:
#   - walker ESP32 (BNO086) powered and broadcasting  (flash: walker-fw/, port ttyUSB3)
#   - a fixed mesh node running mesh_node.c on the node port (default ttyUSB2 = range_a)
#   - board reachable via the Protectli jump; led_from_band.py + run_led.sh present in /home/xilinx
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NODE="${1:-/dev/ttyUSB2}"
echo "[demo] walker band from $NODE  ->  FPGA interpreter -> RGB LED. Shake the walker. Ctrl-C to stop."
python3 -u "$HERE/mesh_bridge.py" "$NODE" \
  | ssh -J "${PPT_JUMP:-adminlocal@192.168.4.2}" "${PPT_BOARD:-xilinx@10.10.10.2}" 'sudo bash /home/xilinx/run_led.sh'
