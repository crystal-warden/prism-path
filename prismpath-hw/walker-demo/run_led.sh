#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
source /etc/profile.d/pynq_venv.sh 2>/dev/null
source /etc/profile.d/xrt_setup.sh 2>/dev/null
source /etc/profile.d/boardname.sh 2>/dev/null
cd /home/xilinx
exec python3 led_from_band.py
