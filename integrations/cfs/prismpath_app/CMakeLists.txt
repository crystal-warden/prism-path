# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
project(CFE_PRISMPATH_APP C)

# PrismPath's embedded evaluator, prismpath-hw/ppt_eval.h, is included from the PrismPath checkout and never
# copied. Point PRISMPATH_HW_DIR (a CMake variable or an environment variable) at that directory. When this
# app is symlinked into a cFS checkout, the link is followed back to the PrismPath checkout automatically.
get_filename_component(_PRISMPATH_APP_REAL "${CMAKE_CURRENT_LIST_DIR}" REALPATH)
if (NOT PRISMPATH_HW_DIR)
  if (DEFINED ENV{PRISMPATH_HW_DIR})
    set(PRISMPATH_HW_DIR "$ENV{PRISMPATH_HW_DIR}")
  else()
    set(PRISMPATH_HW_DIR "${_PRISMPATH_APP_REAL}/../../../prismpath-hw")
  endif()
endif()
if (NOT EXISTS "${PRISMPATH_HW_DIR}/ppt_eval.h")
  message(FATAL_ERROR "prismpath_app: ppt_eval.h not found in PRISMPATH_HW_DIR='${PRISMPATH_HW_DIR}'. "
                      "Set PRISMPATH_HW_DIR to the prismpath-hw directory of a PrismPath checkout.")
endif()

add_cfe_app(prismpath_app
  fsw/src/prismpath_app.c
  fsw/src/prismpath_app_kernel.c
)

target_include_directories(prismpath_app PUBLIC fsw/inc)
target_include_directories(prismpath_app PRIVATE "${PRISMPATH_HW_DIR}")

# the policy image as a cFE table, loaded at startup and replaceable from the ground
add_cfe_tables(prismpath_app fsw/tables/prismpath_app_policy_tbl.c)
