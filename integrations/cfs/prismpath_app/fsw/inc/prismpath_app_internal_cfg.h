/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file PRISMPATH_APP platform configuration. */
#ifndef PRISMPATH_APP_INTERNAL_CFG_H
#define PRISMPATH_APP_INTERNAL_CFG_H

#include "prismpath_app_internal_cfg_values.h"

#define PRISMPATH_APP_PLATFORM_PIPE_DEPTH         PRISMPATH_APP_PLATFORM_CFGVAL(PIPE_DEPTH)
#define DEFAULT_PRISMPATH_APP_PLATFORM_PIPE_DEPTH 32
#define PRISMPATH_APP_PLATFORM_PIPE_NAME          PRISMPATH_APP_PLATFORM_CFGVAL(PIPE_NAME)
#define DEFAULT_PRISMPATH_APP_PLATFORM_PIPE_NAME  "PP_APP_CMD_PIPE" /* OSAL limits an object name to 20 characters */
#define PRISMPATH_APP_PLATFORM_TABLE_FILE         PRISMPATH_APP_PLATFORM_CFGVAL(TABLE_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_TABLE_FILE "/cf/pp_app_policy.tbl"
/** How long the app waits for a message before it checks its table for a ground update, in milliseconds. */
#define PRISMPATH_APP_PLATFORM_TABLE_POLL_MS         PRISMPATH_APP_PLATFORM_CFGVAL(TABLE_POLL_MS)
#define DEFAULT_PRISMPATH_APP_PLATFORM_TABLE_POLL_MS 1000
/** Where the run (receipts, cases, root statements) is written for downlink. */
#define PRISMPATH_APP_PLATFORM_RUN_DIR         PRISMPATH_APP_PLATFORM_CFGVAL(RUN_DIR)
#define DEFAULT_PRISMPATH_APP_PLATFORM_RUN_DIR "/cf/pprun"
/** The authority's raw 32 byte Ed25519 public key: which images may run. A mission builds it into its boot image. */
#define PRISMPATH_APP_PLATFORM_AUTHORITY_FILE         PRISMPATH_APP_PLATFORM_CFGVAL(AUTHORITY_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_AUTHORITY_FILE "/cf/pp_authority.pub"
/** The instance key's raw 32 byte Ed25519 seed: what signs the root statements. Provisioned per vehicle. */
#define PRISMPATH_APP_PLATFORM_INSTANCE_FILE         PRISMPATH_APP_PLATFORM_CFGVAL(INSTANCE_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_INSTANCE_FILE "/cf/pp_instance.key"
/** The Critical Data Store block that holds the run state across a processor reset. */
#define PRISMPATH_APP_PLATFORM_CDS_NAME         PRISMPATH_APP_PLATFORM_CFGVAL(CDS_NAME)
#define DEFAULT_PRISMPATH_APP_PLATFORM_CDS_NAME "PPRunState"

/**
 * The runtime monitor's staleness bound in seconds of mission elapsed time, or 0 when this mission has no monitor.
 * With a bound, the monitor_ok field of the reading is true only while the latest verdict on
 * PRISMPATH_APP_MONITOR_VERDICT_MID is ok and was received within the bound: no verdict yet, a violation and an
 * old verdict all read as not ok. With 0, the field is always true. The build takes the bound from the environment
 * variable PP_MONITOR_STALE_SECS (CMakeLists.txt), so a mission turns the monitor on at build time.
 */
#ifndef PRISMPATH_APP_MONITOR_STALE_SECS
#define PRISMPATH_APP_MONITOR_STALE_SECS 0
#endif

#endif
