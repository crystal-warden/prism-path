/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

#ifndef DEFAULT_PRISMPATH_APP_MSGIDS_H
#define DEFAULT_PRISMPATH_APP_MSGIDS_H

#include "cfe_core_api_base_msgids.h"
#include "prismpath_app_msgid_values.h"

#define PRISMPATH_APP_CMD_MID          PRISMPATH_APP_CMD_PLATFORM_MIDVAL(CMD)
#define PRISMPATH_APP_SEND_HK_MID      PRISMPATH_APP_CMD_PLATFORM_MIDVAL(SEND_HK)
/** The proposed commands: published by the autonomy app, and subscribed to by this app alone. */
#define PRISMPATH_APP_PROPOSED_CMD_MID PRISMPATH_APP_CMD_PLATFORM_MIDVAL(PROPOSED_CMD)
/** The allowed commands, republished here for the vehicle's apps. */
#define PRISMPATH_APP_VEHICLE_CMD_MID  PRISMPATH_APP_CMD_PLATFORM_MIDVAL(VEHICLE_CMD)
#define PRISMPATH_APP_HK_TLM_MID       PRISMPATH_APP_TLM_PLATFORM_MIDVAL(HK_TLM)

#endif
