# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# The C++ embed proof: the certified C11 interpreter compiled unmodified into a C++17
# application. PPT_INTERP_NO_MAIN omits the CLI entry point; everything else is the
# identical certified source.
cmake_minimum_required(VERSION 3.16)
project(prismpath_cpp_example C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(HW ${CMAKE_CURRENT_SOURCE_DIR}/../../prismpath-hw)

add_executable(ppt_replay example.cpp ${HW}/interp.c)
target_include_directories(ppt_replay PRIVATE ${HW})
target_compile_definitions(ppt_replay PRIVATE PPT_INTERP_NO_MAIN)
target_compile_options(ppt_replay PRIVATE -Wall -Wextra)
