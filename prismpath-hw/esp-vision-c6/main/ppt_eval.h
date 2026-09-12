// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// ppt_eval.h: the relay's evaluator is the shared embedded evaluator (prismpath-hw/ppt_eval.h), the one
// every firmware includes and interp_hdr.c certifies on the host. The relay is RISC-V: the same table
// image, the same code, the fifth instruction set on the conformance table. Only the caps are set here.
#pragma once
#define TBL_MAX        8192
#define PPT_MAX_FIELDS 128
#define STACK_MAX      256
#include "../../ppt_eval.h"
