#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# usage: flash_c6.sh <air|host|replay> <port>
set -e; cd "$(dirname "$0")"; source ~/cwprojects/esp-idf/export.sh >/dev/null 2>&1
export C6_APP=$1
idf.py -B build_$1 -D SDKCONFIG=sdkconfig.$1 -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.$1" set-target esp32c6 2>&1 | grep -E 'error' || true
idf.py -B build_$1 -D SDKCONFIG=sdkconfig.$1 -D SDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.$1" build 2>&1 | grep -E 'error|Project build complete' | tail -3
idf.py -B build_$1 -p "$2" flash 2>&1 | grep -E 'Hard resetting|error|Error' | tail -2
