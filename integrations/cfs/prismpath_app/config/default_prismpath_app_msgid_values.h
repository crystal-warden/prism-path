/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

#ifndef DEFAULT_PRISMPATH_APP_MSGID_VALUES_H
#define DEFAULT_PRISMPATH_APP_MSGID_VALUES_H

#include "cfe_core_api_base_msgids.h"
#include "prismpath_app_topicids.h"

#define PRISMPATH_APP_CMD_PLATFORM_MIDVAL(x) CFE_PLATFORM_CMD_TOPICID_TO_MIDV(PRISMPATH_APP_MISSION_##x##_TOPICID)
#define PRISMPATH_APP_TLM_PLATFORM_MIDVAL(x) CFE_PLATFORM_TLM_TOPICID_TO_MIDV(PRISMPATH_APP_MISSION_##x##_TOPICID)

#endif
