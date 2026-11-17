# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# The PrismPath reference deployment for F Prime. The F Prime framework is a checkout beside this repository's
# build area (settings.ini: framework_path), used in place and never copied.
cmake_minimum_required(VERSION 3.26)
cmake_policy(SET CMP0048 NEW)
project(PrismPathRef VERSION 1.0.0 LANGUAGES C CXX)

set(FPRIME_FRAMEWORK_PATH "${CMAKE_CURRENT_LIST_DIR}/../../.cfs-build/fprime" CACHE PATH "F Prime checkout")
include("${FPRIME_FRAMEWORK_PATH}/cmake/FPrime.cmake")
fprime_setup_included_code()
add_fprime_subdirectory("${CMAKE_CURRENT_LIST_DIR}/PrismPathRef/")
