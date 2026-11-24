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

# The receipts' Merkle accumulator is prismpath-ebpf/merkle.h, and the onboard Ed25519 is Monocypher 4.0.2 as
# prismpath-hw/mesh/main vendors it (BSD-2-Clause OR CC0-1.0). Both are compiled from the checkout, never copied.
# merkle.h's SHA-256 is OpenSSL's by default (its seam, PPT_MERKLE_SHA256_EXTERNAL, is where a flight target
# without OpenSSL supplies its own), so the app links libcrypto.
set(PRISMPATH_EBPF_DIR "${PRISMPATH_HW_DIR}/../prismpath-ebpf")
set(PRISMPATH_MONOCYPHER_DIR "${PRISMPATH_HW_DIR}/mesh/main")
foreach(_need "${PRISMPATH_EBPF_DIR}/merkle.h" "${PRISMPATH_MONOCYPHER_DIR}/monocypher-ed25519.c")
  if (NOT EXISTS "${_need}")
    message(FATAL_ERROR "prismpath_app: ${_need} not found; PRISMPATH_HW_DIR must be the prismpath-hw of a PrismPath checkout")
  endif()
endforeach()

# The C core of policy distribution, prismpath-hw/dist, is compiled from the checkout as the mesh firmware compiles it,
# with the bound of a cfs.table (the PP_PolicyTable_t bytes before ImageSig) as its table bound.
set(PRISMPATH_DIST_DIR "${PRISMPATH_HW_DIR}/dist")
if (NOT EXISTS "${PRISMPATH_DIST_DIR}/pp_dist.c")
  message(FATAL_ERROR "prismpath_app: ${PRISMPATH_DIST_DIR}/pp_dist.c not found; PRISMPATH_HW_DIR must be the prismpath-hw of a PrismPath checkout")
endif()

add_cfe_app(prismpath_app
  fsw/src/prismpath_app.c
  fsw/src/prismpath_app_kernel.c
  fsw/src/prismpath_app_run.c
  fsw/src/prismpath_app_dist.c
  "${PRISMPATH_DIST_DIR}/pp_dist.c"
  "${PRISMPATH_MONOCYPHER_DIR}/monocypher.c"
  "${PRISMPATH_MONOCYPHER_DIR}/monocypher-ed25519.c"
)
target_compile_definitions(prismpath_app PRIVATE PP_TABLE_MAX=4692)

# a mission with a runtime monitor sets the staleness bound of its verdict (seconds) when it builds
if (DEFINED ENV{PP_MONITOR_STALE_SECS})
  target_compile_definitions(prismpath_app PRIVATE PRISMPATH_APP_MONITOR_STALE_SECS=$ENV{PP_MONITOR_STALE_SECS})
endif()

target_include_directories(prismpath_app PUBLIC fsw/inc "${PRISMPATH_EBPF_DIR}" "${PRISMPATH_MONOCYPHER_DIR}" "${PRISMPATH_DIST_DIR}")
target_include_directories(prismpath_app PRIVATE "${PRISMPATH_HW_DIR}")
# as a link flag, not a bare name: a mission may define a CMake target called crypto of its own (NOS3 does)
target_link_libraries(prismpath_app -lcrypto)

# the policy image as a cFE table, loaded at startup and replaceable from the ground
add_cfe_tables(prismpath_app fsw/tables/prismpath_app_policy_tbl.c)
