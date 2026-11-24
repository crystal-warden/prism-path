/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The reading layout: which bytes of a proposed command's payload are which field of the policy.
 *
 * One row per field, in the policy's register order (the field names sorted, which is the order
 * policy/gen_image.py gives the compiled image). Each row is
 *
 *   X(register, "name", KIND, payload_offset, width_bytes, min, max, ROLE)
 *
 * where KIND is INT, BOOL or MONITOR, the offset counts from the first byte after the command header, the width is
 * 1 or 2 bytes (unsigned, little endian) and min and max are the field definition's bounds, which a
 * bool carries as 0 and 1. A value outside its bounds is the core's boundary refusal
 * (route:contract-violation), made before any rule is read.
 *
 * ROLE is the label an action floor is held to (docs/design/spec-policy-distribution.md AF9, AF10): COMMAND, the one
 * field that names the action, PARAMETER, a parameter of the command, which every floor rule bounds from both sides,
 * INDEPENDENT, a reading of the world the app takes from a source other than the proposer, which a floor rule may
 * test while it is fresh, and PROPOSER, a reading the proposer writes, which no floor rule may test. The labels are in
 * the layout hash, so a table is built for them. The independent field's staleness bound is the monitor's,
 * PRISMPATH_APP_MONITOR_STALE_SECS: a mission with no monitor (bound 0) has no independent source, and the app then
 * gives its floor checks the field as the proposer's, so no floor can test a verdict nobody gives.
 *
 * MONITOR is a bool the app supplies and the proposer does not: the runtime monitor's verdict, read from the
 * monitor's message with its staleness bound (PRISMPATH_APP_MONITOR_STALE_SECS). Its byte in the command is
 * overwritten by the app on every proposal, and the policy reads the app's value, never the proposer's.
 *
 * tests/test_cfs_app.py reads this table and holds it to the example policy's field definitions, and the
 * kernel hashes it at run time against the hash the policy table carries, so an image written for another
 * layout never activates. Edit the policy and this table together.
 */
#ifndef PRISMPATH_APP_LAYOUT_H
#define PRISMPATH_APP_LAYOUT_H

#define PRISMPATH_APP_FIELDS(X)                                   \
    X(0, "cmd_class",      INT,     0, 1, 0,   10,  COMMAND)         \
    X(1, "ground_contact", BOOL,    1, 1, 0,   1,   PROPOSER)        \
    X(2, "monitor_ok",     MONITOR, 6, 1, 0,   1,   INDEPENDENT)     \
    X(3, "slew_deg",       INT,     2, 2, 0,   180, PARAMETER)       \
    X(4, "thrust_pct",     INT,     4, 2, 0,   200, PARAMETER)

/** Number of fields. */
#define PRISMPATH_APP_FIELD_COUNT 5
/** Bytes of payload a proposed command must carry (the highest offset plus its width, rounded up to 2, and the spare word). */
#define PRISMPATH_APP_PAYLOAD_LEN 10

#endif
