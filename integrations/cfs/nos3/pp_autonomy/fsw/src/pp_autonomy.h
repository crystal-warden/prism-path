/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The scenario's autonomy app: its ground command, function codes and event ids. */
#ifndef PP_AUTONOMY_H
#define PP_AUTONOMY_H

/** Ground commands to the autonomy app, clear of every message id NOS3 and the PrismPath app use. */
#define PP_AUTONOMY_CMD_MID 0x18C4

#define PP_AUTONOMY_NOOP_CC  0
#define PP_AUTONOMY_START_CC 1 /**< start proposing the plan */

#define PP_AUTONOMY_INIT_EID           1
#define PP_AUTONOMY_NOOP_EID           2
#define PP_AUTONOMY_START_EID          3
#define PP_AUTONOMY_PROPOSE_EID        10
#define PP_AUTONOMY_PLAN_DONE_EID      11
#define PP_AUTONOMY_PAYLOAD_STATUS_EID 12
#define PP_AUTONOMY_FAULT_EID          13

void PP_AUTONOMY_Main(void);

#endif
