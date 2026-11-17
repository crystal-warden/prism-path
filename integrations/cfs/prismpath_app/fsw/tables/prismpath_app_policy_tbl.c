/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The example policy table: the image policy/gen_image.py built from policy/example.core.json. A mission
 *   builds its own by pointing this file at its own generated include. The two signatures are left zero here:
 *   the authority signs the built table file on the ground (integrations/cfs/ground/table.py), and the app refuses
 *   a table whose signatures do not verify. */
#include "cfe_tbl_filedef.h" /* the CFE_TBL_FILEDEF macro */
#include "prismpath_app_msg.h"

#include "prismpath_app_policy_image.inc"

PRISMPATH_APP_PolicyTable_t PolicyTable = {
    .LayoutHash    = PRISMPATH_APP_EXAMPLE_LAYOUT_HASH,
    .ImageLen      = PRISMPATH_APP_EXAMPLE_IMAGE_LEN,
    .RuleCount     = PRISMPATH_APP_EXAMPLE_RULE_COUNT,
    .ContractCause = PRISMPATH_APP_EXAMPLE_CONTRACT_CAUSE,
    .NoMatchCause  = PRISMPATH_APP_EXAMPLE_NOMATCH_CAUSE,
    .Version       = PRISMPATH_APP_EXAMPLE_VERSION,
    .CoreLen       = PRISMPATH_APP_EXAMPLE_CORE_LEN,
    .FlowJsonLen   = PRISMPATH_APP_EXAMPLE_FLOW_JSON_LEN,
    .Rules         = PRISMPATH_APP_EXAMPLE_RULES,
    .Image         = PRISMPATH_APP_EXAMPLE_IMAGE,
    .Core          = PRISMPATH_APP_EXAMPLE_CORE,
    .FlowJson      = PRISMPATH_APP_EXAMPLE_FLOW_JSON,
};

/* the structure type, the table name in the file header, a description, and the file the build writes */
CFE_TBL_FILEDEF(PolicyTable, PRISMPATH_APP.PolicyTable, PrismPath policy image, pp_app_policy.tbl)
