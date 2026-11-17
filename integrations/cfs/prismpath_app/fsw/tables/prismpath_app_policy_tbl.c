/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The example policy table: the image policy/gen_image.py built from policy/example.core.json. A mission
 *   builds its own by pointing this file at its own generated include. */
#include "cfe_tbl_filedef.h" /* the CFE_TBL_FILEDEF macro */
#include "prismpath_app_msg.h"

#include "prismpath_app_policy_image.inc"

PRISMPATH_APP_PolicyTable_t PolicyTable = {
    .LayoutHash    = PRISMPATH_APP_EXAMPLE_LAYOUT_HASH,
    .ImageLen      = PRISMPATH_APP_EXAMPLE_IMAGE_LEN,
    .RuleCount     = PRISMPATH_APP_EXAMPLE_RULE_COUNT,
    .ContractCause = PRISMPATH_APP_EXAMPLE_CONTRACT_CAUSE,
    .NoMatchCause  = PRISMPATH_APP_EXAMPLE_NOMATCH_CAUSE,
    .Rules         = PRISMPATH_APP_EXAMPLE_RULES,
    .Image         = PRISMPATH_APP_EXAMPLE_IMAGE,
};

/* the structure type, the table name in the file header, a description, and the file the build writes */
CFE_TBL_FILEDEF(PolicyTable, PRISMPATH_APP.PolicyTable, PrismPath policy image, pp_app_policy.tbl)
