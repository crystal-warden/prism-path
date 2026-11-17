# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
register_fprime_module(
    AUTOCODER_INPUTS
        "${CMAKE_CURRENT_LIST_DIR}/Proposer.fpp"
    SOURCES
        "${CMAKE_CURRENT_LIST_DIR}/Proposer.cpp"
    DEPENDS
        Fw_Cmd
        Fw_Com
)
