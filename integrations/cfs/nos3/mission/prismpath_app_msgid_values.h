/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   Message id values in the NOS3 mission. NOS3's cFE predates topic ids (it has no cfe_core_api_base_msgids.h),
 *   so a message id is the message id version 1 base, 0x1800 for commands and 0x0800 for telemetry, plus the topic. */
#ifndef PRISMPATH_APP_MSGID_VALUES_H
#define PRISMPATH_APP_MSGID_VALUES_H

#include "prismpath_app_topicids.h"

#define PRISMPATH_APP_CMD_PLATFORM_MIDVAL(x) (0x1800 | PRISMPATH_APP_MISSION_##x##_TOPICID)
#define PRISMPATH_APP_TLM_PLATFORM_MIDVAL(x) (0x0800 | PRISMPATH_APP_MISSION_##x##_TOPICID)

#endif
