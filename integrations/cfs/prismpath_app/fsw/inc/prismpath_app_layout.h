/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The reading layout: which bytes of a proposed command's payload are which field of the policy.
 *
 * One row per field, in the policy's register order (the field names sorted, which is the order
 * policy/gen_image.py gives the compiled image). Each row is
 *
 *   X(register, "name", KIND, payload_offset, width_bytes, min, max)
 *
 * where KIND is INT, BOOL or MONITOR, the offset counts from the first byte after the command header, the width is
 * 1 or 2 bytes (unsigned, little endian) and min and max are the field definition's bounds, which a
 * bool carries as 0 and 1. A value outside its bounds is the core's boundary refusal
 * (route:contract-violation), made before any rule is read.
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

#define PRISMPATH_APP_FIELDS(X)                      \
    X(0, "cmd_class",      INT,     0, 1, 0,   10)    \
    X(1, "ground_contact", BOOL,    1, 1, 0,   1)     \
    X(2, "monitor_ok",     MONITOR, 6, 1, 0,   1)     \
    X(3, "slew_deg",       INT,     2, 2, 0,   180)   \
    X(4, "thrust_pct",     INT,     4, 2, 0,   200)

/** Number of fields. */
#define PRISMPATH_APP_FIELD_COUNT 5
/** Bytes of payload a proposed command must carry (the highest offset plus its width, rounded up to 2, and the spare word). */
#define PRISMPATH_APP_PAYLOAD_LEN 10

#endif
