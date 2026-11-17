/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The PrismPath app's topic ids in the NOS3 mission. The app's defaults (0xE0 to 0xE3) collide with NOS3's
 *   own apps, so this mission override moves them to 0xC0 to 0xC3, clear of every message id NOS3 defines.
 *   integrations/cfs/nos3/run_nos3_scenario.py stages it into NOS3's mission definitions. */
#ifndef PRISMPATH_APP_TOPICID_VALUES_H
#define PRISMPATH_APP_TOPICID_VALUES_H

#define PRISMPATH_APP_MISSION_TIDVAL(x) PP_NOS3_PRISMPATH_APP_##x##_TOPICID

#define PP_NOS3_PRISMPATH_APP_CMD_TOPICID          0xC0
#define PP_NOS3_PRISMPATH_APP_SEND_HK_TOPICID      0xC1
#define PP_NOS3_PRISMPATH_APP_PROPOSED_CMD_TOPICID 0xC2
#define PP_NOS3_PRISMPATH_APP_VEHICLE_CMD_TOPICID  0xC3
#define PP_NOS3_PRISMPATH_APP_HK_TLM_TOPICID       0xC1

#endif
