# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# The NOS3 scenario's autonomy app. It reads NOS3's sample instrument housekeeping, so it builds only inside a NOS3
# mission, where the mission's include list names the sample component's headers.
cmake_minimum_required(VERSION 3.5)
project(PP_AUTONOMY C)

include_directories(${APPLICATION_PLATFORM_INC_LIST})
include_directories(${hwlib_MISSION_DIR}/fsw/public_inc)
include_directories(${prismpath_app_MISSION_DIR}/fsw/inc)

add_cfe_app(pp_autonomy fsw/src/pp_autonomy.c)
