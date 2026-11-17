# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# The NOS3 scenario's runtime monitor app: NASA's R2U2 (C version, Apache-2.0 or MIT) running a compiled temporal
# property over the payload's housekeeping. R2U2's sources are compiled from a checkout of its public repository
# and never copied into this repository: set PP_R2U2_DIR to that checkout (the scenario script does). It builds only
# inside a NOS3 mission, where the mission's include list names the sample component's headers.
cmake_minimum_required(VERSION 3.5)
project(PP_MONITOR C)

if (NOT DEFINED ENV{PP_R2U2_DIR} OR NOT EXISTS "$ENV{PP_R2U2_DIR}/monitors/c/src/r2u2.h")
  message(FATAL_ERROR "pp_monitor: set PP_R2U2_DIR to a checkout of https://github.com/R2U2/r2u2 (monitors/c/src/r2u2.h)")
endif()
set(R2U2_SRC "$ENV{PP_R2U2_DIR}/monitors/c/src")
file(GLOB_RECURSE R2U2_SOURCES "${R2U2_SRC}/lib.c" "${R2U2_SRC}/internals/*.c" "${R2U2_SRC}/instructions/*.c"
     "${R2U2_SRC}/engines/*.c" "${R2U2_SRC}/memory/*.c")

include_directories(${APPLICATION_PLATFORM_INC_LIST})
include_directories(${hwlib_MISSION_DIR}/fsw/public_inc)
include_directories(${prismpath_app_MISSION_DIR}/fsw/inc)

add_cfe_app(pp_monitor fsw/src/pp_monitor.c ${R2U2_SOURCES})
# R2U2 is a third party library built with its own flags, not the mission's -Werror set
set_source_files_properties(${R2U2_SOURCES} PROPERTIES COMPILE_FLAGS "-w -std=c99 -D_POSIX_C_SOURCE=200112L")
# this app includes r2u2.h, whose binary constants the mission's -pedantic -Werror reject
set_source_files_properties(fsw/src/pp_monitor.c PROPERTIES COMPILE_FLAGS "-Wno-pedantic")
target_include_directories(pp_monitor PRIVATE "${R2U2_SRC}" "${R2U2_SRC}/internals" "${R2U2_SRC}/instructions"
                           "${R2U2_SRC}/engines" "${R2U2_SRC}/memory")
