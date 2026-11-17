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

#endif
