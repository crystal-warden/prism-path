#!/usr/bin/env bash
# deploy.sh — edit-to-silicon: <flow.md> → table image → board BRAM. No resynthesis,
# bitstream hash unchanged; the board's watcher hot-reloads mid-stream.
#   ./deploy.sh prismpath/gallery/incident_severity/incident_severity.md <board-ip>
set -euo pipefail
FLOW=${1:?usage: deploy.sh <flow.md> <board-host>}
BOARD=${2:?usage: deploy.sh <flow.md> <board-host>}
HERE=$(dirname "$(readlink -f "$0")")
T0=$(date +%s%3N)

python3 "$HERE/ppt_compile.py" "$FLOW" -o /tmp/live.ppt --json /tmp/live.json
sha256sum /tmp/live.ppt

# json first, then ppt — the board watcher keys on the .ppt mtime
scp -q /tmp/live.json "xilinx@$BOARD:/home/xilinx/live.json"
scp -q /tmp/live.ppt  "xilinx@$BOARD:/home/xilinx/live.ppt"

echo "deployed in $(( $(date +%s%3N) - T0 ))ms — watch the board console for TABLE RELOADED"
