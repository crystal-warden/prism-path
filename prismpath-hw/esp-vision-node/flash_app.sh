#!/bin/bash
# Build one entry point and flash it. usage: flash_app.sh <t0|snap|rec|replay|live|radio|relay> <uart port>
# The entry point is chosen at CMake configure time, so every switch reconfigures; a plain build after a
# change of VISION_APP keeps the previous app (learned 2026-09-10 when both boards came up as radio nodes).
set -e
cd "$(dirname "$0")"; source ~/cwprojects/esp-idf/export.sh >/dev/null 2>&1
VISION_APP=$1 idf.py reconfigure build 2>&1 | grep -E 'error|Project build complete' | tail -1
idf.py -p "$2" -b 921600 flash 2>&1 | grep -E 'Hard resetting|error' | tail -1
