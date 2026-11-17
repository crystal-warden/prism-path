/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The scenario's runtime monitor app: its ground command, function codes and event ids. */
#ifndef PP_MONITOR_H
#define PP_MONITOR_H

/** Ground commands to the monitor app, clear of every message id NOS3 and the PrismPath app use. */
#define PP_MONITOR_CMD_MID 0x18C6

#define PP_MONITOR_NOOP_CC   0
#define PP_MONITOR_HALT_CC   1 /**< stop publishing verdicts (the monitor goes quiet, as if it had hung) */
#define PP_MONITOR_RESUME_CC 2 /**< publish verdicts again */

#define PP_MONITOR_INIT_EID    1
#define PP_MONITOR_NOOP_EID    2
#define PP_MONITOR_HALT_EID    3
#define PP_MONITOR_RESUME_EID  4
#define PP_MONITOR_ERR_EID     5
#define PP_MONITOR_VERDICT_EID 10 /**< the verdict changed */

void PP_MONITOR_Main(void);

#endif
