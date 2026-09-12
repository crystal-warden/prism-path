# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# The 802.15.4 hop for decision sufficient vision, on two Seeed XIAO ESP32C6 boards.
#   relay_air:  ESP-NOW in from the camera node, 802.15.4 out (the constrained link)
#   relay_host: 802.15.4 in, native USB out to the host, the same ENF1 records the S3 relay sent
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(vision_c6)
