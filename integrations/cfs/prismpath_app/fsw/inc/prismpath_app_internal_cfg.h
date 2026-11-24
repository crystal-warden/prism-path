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
 * What the app does after a processor reset when the store holds a run state that does not read, so the highest
 * accepted image version is lost. PP_LOST_FLOOR_LOCK, the default, begins a new run that admits no image, so every
 * proposal is refused, until ground deletes the store (cFE ES Delete CDS, with the app stopped) and restarts the app.
 * PP_LOST_FLOOR_MINIMUM begins a new run that admits every image of PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_VERSION
 * and up, so the app keeps deciding, and an older image at or above that version can be activated again. A mission
 * picks by what its workload can bear. A power-on reset clears the store, and the floor, in both.
 */
#define PRISMPATH_APP_PLATFORM_LOST_FLOOR                     PRISMPATH_APP_PLATFORM_CFGVAL(LOST_FLOOR)
#define DEFAULT_PRISMPATH_APP_PLATFORM_LOST_FLOOR             PP_LOST_FLOOR_LOCK
/** Under PP_LOST_FLOOR_MINIMUM, the lowest distribution `seq` the new floor admits (Q5): the floor is one below it. */
#define PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_SEQ             PRISMPATH_APP_PLATFORM_CFGVAL(LOST_FLOOR_MIN_SEQ)
#define DEFAULT_PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_SEQ     1

/**
 * What the app does when its release expires (docs/design/spec-policy-distribution.md X6), beside the lost floor
 * response. PP_EXPIRY_REFUSE, the default, lets the release lapse: the app has no policy, every proposal is refused
 * and the state record says lapsed with dist:expired. PP_EXPIRY_HOLD keeps the expired release deciding until a
 * release that passes every rule replaces it or a revocation ends the hold (X7, X8): the app sets bit 5 in every state
 * record, sends an event when the hold begins and when it ends, and marks its receipts by opening a new case of the
 * core run at each, whose case line says "hold":true. The PEP is provisioned with the setting and refuses to start
 * under the other one (X10).
 */
#define PRISMPATH_APP_PLATFORM_EXPIRY_RESPONSE         PRISMPATH_APP_PLATFORM_CFGVAL(EXPIRY_RESPONSE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_EXPIRY_RESPONSE PP_EXPIRY_REFUSE

/** The trust anchor (`prismpath.dist-trust/2`) the ground's provisioning writes, and where the app keeps what it holds
 *  of policy distribution: the releases and the first copy of the install record and its sets (IS10). */
#define PRISMPATH_APP_PLATFORM_ANCHOR_FILE         PRISMPATH_APP_PLATFORM_CFGVAL(ANCHOR_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_ANCHOR_FILE "/cf/pp_trust.anchor"
#define PRISMPATH_APP_PLATFORM_DIST_DIR            PRISMPATH_APP_PLATFORM_CFGVAL(DIST_DIR)
#define DEFAULT_PRISMPATH_APP_PLATFORM_DIST_DIR    "/cf/ppdist"
/** The statements provisioning brings (P2 step 3), /cf/pp_bring0.pps and up, and the boot release, /cf/pp_boot0.pps
 *  and up, which the app stages and commits as if offered when it starts with no release active. */
#define PRISMPATH_APP_PLATFORM_BRING_FILE          PRISMPATH_APP_PLATFORM_CFGVAL(BRING_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_BRING_FILE  "/cf/pp_bring%u.pps"
#define PRISMPATH_APP_PLATFORM_BOOT_FILE           PRISMPATH_APP_PLATFORM_CFGVAL(BOOT_FILE)
#define DEFAULT_PRISMPATH_APP_PLATFORM_BOOT_FILE   "/cf/pp_boot%u.pps"
/** The Critical Data Store area of the second copy of the install record and its sets (IS10). */
#define PRISMPATH_APP_PLATFORM_COPY_CDS_NAME         PRISMPATH_APP_PLATFORM_CFGVAL(COPY_CDS_NAME)
#define DEFAULT_PRISMPATH_APP_PLATFORM_COPY_CDS_NAME "PPInstall"
/** Seconds from the Unix epoch to the mission's time epoch (cFE's 1980-001 by default), so the app's time, which
 *  distribution envelopes are held to, is Unix seconds. */
#define PRISMPATH_APP_PLATFORM_EPOCH_UNIX         PRISMPATH_APP_PLATFORM_CFGVAL(EPOCH_UNIX)
#define DEFAULT_PRISMPATH_APP_PLATFORM_EPOCH_UNIX 315532800LL

/**
 * The runtime monitor's staleness bound in seconds of mission elapsed time, or 0 when this mission has no monitor.
 * With a bound, the monitor_ok field of the reading is true only while the latest verdict on
 * PRISMPATH_APP_MONITOR_VERDICT_MID is ok and was received within the bound: no verdict yet, a violation and an
 * old verdict all read as not ok. With 0, the field is always true for a release's rules, and an action floor can
 * never test it: the layout then labels it the proposer's, so a floor rule that tests it is dist:floor-broad (AF10).
 * The build takes the bound from the environment variable PP_MONITOR_STALE_SECS (CMakeLists.txt), so a mission turns
 * the monitor on at build time.
 */
#ifndef PRISMPATH_APP_MONITOR_STALE_SECS
#define PRISMPATH_APP_MONITOR_STALE_SECS 0
#endif

#endif
