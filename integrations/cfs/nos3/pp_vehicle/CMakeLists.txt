# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# The NOS3 scenario's vehicle app: allowed commands to NOS3's reaction wheel and sample instrument apps.
cmake_minimum_required(VERSION 3.5)
project(PP_VEHICLE C)

include_directories(${APPLICATION_PLATFORM_INC_LIST})
include_directories(${hwlib_MISSION_DIR}/fsw/public_inc)
include_directories(${prismpath_app_MISSION_DIR}/fsw/inc)

add_cfe_app(pp_vehicle fsw/src/pp_vehicle.c)
