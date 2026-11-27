# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# A relay of the frame binding (spec-policy-distribution.md B10) on an ESP32-C6: ESP-NOW on one side, a UART to a
# PEP with no radio of its own on the other. It holds no key and verifies nothing.
#   . ~/cwprojects/esp-idf/export.sh && idf.py set-target esp32c6 && idf.py build
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(pp_relay_c6)
