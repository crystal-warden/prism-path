/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The PrismPath app's message ids in the NOS3 mission: the app's own names, from the values above. */
#ifndef PRISMPATH_APP_MSGIDS_H
#define PRISMPATH_APP_MSGIDS_H

#include "prismpath_app_msgid_values.h"

#define PRISMPATH_APP_CMD_MID          PRISMPATH_APP_CMD_PLATFORM_MIDVAL(CMD)
#define PRISMPATH_APP_SEND_HK_MID      PRISMPATH_APP_CMD_PLATFORM_MIDVAL(SEND_HK)
#define PRISMPATH_APP_PROPOSED_CMD_MID PRISMPATH_APP_CMD_PLATFORM_MIDVAL(PROPOSED_CMD)
#define PRISMPATH_APP_VEHICLE_CMD_MID  PRISMPATH_APP_CMD_PLATFORM_MIDVAL(VEHICLE_CMD)
#define PRISMPATH_APP_HK_TLM_MID       PRISMPATH_APP_TLM_PLATFORM_MIDVAL(HK_TLM)

#endif
