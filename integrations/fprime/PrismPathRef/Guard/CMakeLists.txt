# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# The guard's decision and receipt code is the cFS app's C, compiled from where it lives (never copied):
#   integrations/cfs/prismpath_app/fsw/src/prismpath_app_kernel.c   the decision core, over prismpath-hw/ppt_eval.h
#   integrations/cfs/prismpath_app/fsw/src/prismpath_app_run.c      the receipts, over prismpath-ebpf/merkle.h
#   prismpath-hw/mesh/main/monocypher*.c                            Ed25519, as the ESP32 mesh vendors it
# merkle.h's SHA-256 is OpenSSL's by default, so the guard links libcrypto.
get_filename_component(_PP_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../../.." ABSOLUTE)
set(_PP_CFS "${_PP_ROOT}/integrations/cfs/prismpath_app/fsw")
set(_PP_MONO "${_PP_ROOT}/prismpath-hw/mesh/main")
foreach(_need "${_PP_CFS}/src/prismpath_app_run.c" "${_PP_ROOT}/prismpath-hw/ppt_eval.h"
              "${_PP_ROOT}/prismpath-ebpf/merkle.h" "${_PP_MONO}/monocypher-ed25519.c")
  if (NOT EXISTS "${_need}")
    message(FATAL_ERROR "PrismPathRef: ${_need} not found; this deployment builds inside a PrismPath checkout")
  endif()
endforeach()

find_package(OpenSSL REQUIRED)

# F Prime builds only sources that live under one of its build roots, and these live elsewhere in the checkout, so they
# are a plain CMake library that the component links.
add_library(prismpath_core STATIC
    "${_PP_CFS}/src/prismpath_app_kernel.c"
    "${_PP_CFS}/src/prismpath_app_run.c"
    "${_PP_MONO}/monocypher.c"
    "${_PP_MONO}/monocypher-ed25519.c")
set_target_properties(prismpath_core PROPERTIES C_STANDARD 11 POSITION_INDEPENDENT_CODE ON)
target_include_directories(prismpath_core PUBLIC
    "${_PP_CFS}/inc" "${_PP_ROOT}/prismpath-hw" "${_PP_ROOT}/prismpath-ebpf" "${_PP_MONO}")
# the receipts name this framework as the decider; nothing else in a receipt differs from the cFS app's
target_compile_definitions(prismpath_core PRIVATE PP_RUN_DECIDER="fprime:prismpath_guard")
target_link_libraries(prismpath_core PUBLIC OpenSSL::Crypto)

register_fprime_module(
    AUTOCODER_INPUTS
        "${CMAKE_CURRENT_LIST_DIR}/Guard.fpp"
    SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/Guard.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/GuardCore.c"
    DEPENDS
        Fw_Cmd
        Fw_Com
)
target_link_libraries(${FPRIME_CURRENT_MODULE} PUBLIC prismpath_core)
