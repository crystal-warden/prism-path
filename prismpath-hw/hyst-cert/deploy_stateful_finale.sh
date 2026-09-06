#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# deploy_stateful_finale.sh — pull the stateful finale overlay from the Windows rig, land it on the
# board with the signed hyst_band policy + cert kit, and run silicon re-cert leg 1.
#
# Run from gx10. Stops the finale service first (safe quiesce), backs up the PROVEN overlay files
# on the board (ppt_finale.bit/.hwh -> .pre_stateful), deploys, re-certs, and leaves the service
# STOPPED for the interactive legs (auto-mode sweep + WCET re-witness). Restart it only after the
# operator legs pass: sudo systemctl start prismpath-finale.service
set -euo pipefail

WIN="${PPT_WIN:?set PPT_WIN (user@windows-vivado-host)}"
WINDIR="${PPT_WINDIR:?set PPT_WINDIR (path to build_overlay_finale on the Vivado host)}"
JUMP="${PPT_JUMP:-adminlocal@192.168.4.2}"
BOARD="${PPT_BOARD:-xilinx@10.10.10.2}"
HERE="$(cd "$(dirname "$0")" && pwd)"
FLOWS="$HERE/../demo/flows"
STAGE=/tmp/stateful_finale_deploy

echo "== 1/5 pull bit+hwh+reports from the Windows rig =="
rm -rf "$STAGE" && mkdir -p "$STAGE"
scp "$WIN:$WINDIR/ppt_finale.bit" "$STAGE/ppt_finale.bit"
scp "$WIN:$WINDIR/ppt_finale.hwh" "$STAGE/ppt_finale.hwh"
scp "$WIN:$WINDIR/timing.rpt" "$STAGE/timing.rpt" || echo "(no timing.rpt)"
scp "$WIN:$WINDIR/utilization.rpt" "$STAGE/utilization.rpt" || echo "(no utilization.rpt)"
grep -E "WNS|Worst Negative Slack|Timing constraints are met|violated" "$STAGE/timing.rpt" | head -5 || true
sha256sum "$STAGE"/ppt_finale.* | tee "$STAGE/SHA256SUMS"

echo "== 2/5 stop the finale service + back up the proven overlay =="
ssh -J "$JUMP" "$BOARD" "sudo systemctl stop prismpath-finale.service 2>/dev/null; \
  sudo cp -n /home/xilinx/ppt_finale.bit /home/xilinx/ppt_finale.bit.pre_stateful 2>/dev/null; \
  sudo cp -n /home/xilinx/ppt_finale.hwh /home/xilinx/ppt_finale.hwh.pre_stateful 2>/dev/null; \
  echo board backup done"

echo "== 3/5 land overlay + signed policy + corpus + cert kit =="
scp -J "$JUMP" "$STAGE/ppt_finale.bit" "$STAGE/ppt_finale.hwh" "$BOARD:/tmp/"
scp -J "$JUMP" "$FLOWS/hyst_band.ppt" "$FLOWS/hyst_band.json" \
    "$FLOWS/hyst_band.ppt.manifest.json" "$FLOWS/hyst_band.ppt.manifest.sig" \
    "$FLOWS/hyst_corpus.json" "$HERE/cert_hyst_board.py" "$HERE/oled_live_v2.py" \
    "$HERE/load_new_overlay.py" "$BOARD:/tmp/"
ssh -J "$JUMP" "$BOARD" "sudo mv /tmp/ppt_finale.bit /tmp/ppt_finale.hwh /home/xilinx/ && \
  sudo mv /tmp/hyst_band.* /tmp/hyst_corpus.json /tmp/cert_hyst_board.py /tmp/oled_live_v2.py /tmp/load_new_overlay.py /home/xilinx/ && \
  sudo chown xilinx:xilinx /home/xilinx/ppt_finale.* /home/xilinx/hyst_* /home/xilinx/cert_hyst_board.py /home/xilinx/oled_live_v2.py /home/xilinx/load_new_overlay.py && \
  echo landed"

echo "== 4/5 load the NEW overlay (PptOverlay asserts MAGIC) =="
ssh -J "$JUMP" "$BOARD" "sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh 2>/dev/null; source /etc/profile.d/boardname.sh 2>/dev/null; \
  cd /home/xilinx && python3 load_new_overlay.py'"

echo "== 5/5 silicon re-cert leg 1 (PS-mode sequence replay, 4568 events) =="
ssh -J "$JUMP" "$BOARD" "sudo bash -c 'source /etc/profile.d/pynq_venv.sh; source /etc/profile.d/xrt_setup.sh 2>/dev/null; source /etc/profile.d/boardname.sh 2>/dev/null; \
  cd /home/xilinx && timeout 600 python3 cert_hyst_board.py hyst_corpus.json hyst_band.ppt hyst_band.json'" | tail -8

echo ""
echo "NEXT (operator): leg 2 auto sweep  ->  cert_hyst_board.py ... --auto  (sweep the pot)"
echo "      then WCET-on-pins re-witness, then systemctl start prismpath-finale.service"
