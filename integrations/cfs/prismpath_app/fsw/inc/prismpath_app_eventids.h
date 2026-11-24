/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file PRISMPATH_APP event IDs. */
#ifndef PRISMPATH_APP_EVENTIDS_H
#define PRISMPATH_APP_EVENTIDS_H

#define PRISMPATH_APP_RESERVED_EID        0
#define PRISMPATH_APP_INIT_INF_EID        1
#define PRISMPATH_APP_CC_ERR_EID          2
#define PRISMPATH_APP_NOOP_INF_EID        3
#define PRISMPATH_APP_RESET_INF_EID       4
#define PRISMPATH_APP_MID_ERR_EID         5
#define PRISMPATH_APP_CMD_LEN_ERR_EID     6
#define PRISMPATH_APP_PIPE_ERR_EID        7
#define PRISMPATH_APP_CR_PIPE_ERR_EID     8
#define PRISMPATH_APP_SUB_ERR_EID         9
#define PRISMPATH_APP_TABLE_REG_ERR_EID   10
#define PRISMPATH_APP_ALLOW_EID           20 /* a proposed command was allowed and republished */
#define PRISMPATH_APP_REFUSE_EID          21 /* refused, with the registered cause code */
#define PRISMPATH_APP_ESCALATE_EID        22 /* escalated, with the registered cause code; not forwarded */
#define PRISMPATH_APP_FORWARD_ERR_EID     23 /* an allowed command could not be sent on the software bus */
#define PRISMPATH_APP_POLICY_LOADED_EID   24 /* a policy image passed the kernel's checks and is active */
#define PRISMPATH_APP_POLICY_REJECTED_EID 25 /* a policy image failed the kernel's checks and was not activated */
#define PRISMPATH_APP_HK_INF_EID          26 /* the counters, at each housekeeping request */
#define PRISMPATH_APP_RECORD_ERR_EID      27 /* a decision could not be receipted; an allowed command is withheld */
#define PRISMPATH_APP_SEALED_EID          28 /* a root statement was signed and the run written for downlink */
#define PRISMPATH_APP_SEAL_ERR_EID        29 /* a seal failed (no key, or a file error) */
#define PRISMPATH_APP_STATE_INF_EID       30 /* the run state at startup: restored from the CDS or begun fresh */
#define PRISMPATH_APP_STATE_ERR_EID       31 /* the CDS or the run files could not be used as recorded */
#define PRISMPATH_APP_KEY_ERR_EID         32 /* a key file is missing or unreadable */
#define PRISMPATH_APP_DIST_INF_EID        33 /* a state record of policy distribution: staged, committed, refused... */
#define PRISMPATH_APP_DIST_ERR_EID        34 /* a frame dropped, the table service refused a switch, a start refused */
#define PRISMPATH_APP_HELD_EID            35 /* X7: a hold began (the release expired and the mission holds) or ended */
#define PRISMPATH_APP_PROVISIONED_EID     36 /* P2 step 4: the anchor's fingerprint and each install statement held */
#define PRISMPATH_APP_NOT_ENACTED_EID     37 /* RC4: a decision of the action floor or the fallback policy, refused */

#endif
