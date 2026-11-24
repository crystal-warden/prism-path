/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file PRISMPATH_APP ground command function codes. */
#ifndef PRISMPATH_APP_FCNCODES_H
#define PRISMPATH_APP_FCNCODES_H

#define PRISMPATH_APP_NOOP_CC           0
#define PRISMPATH_APP_RESET_COUNTERS_CC 1
#define PRISMPATH_APP_SEAL_CC           2 /* sign a root statement over every receipt and write the run for downlink */
/* policy distribution (docs/design/spec-policy-distribution.md, section 8.3): each carries one frame of the frame
 * binding, so a table is admitted by its distribution envelope, offered on the software bus */
#define PRISMPATH_APP_OFFER_CC          3 /* an offer frame: a sealed envelope and its body follow */
#define PRISMPATH_APP_CHUNK_CC          4 /* a chunk frame of the sealed envelope or of the body */
#define PRISMPATH_APP_CONTROL_CC        5 /* a commit frame, with the table's image attestation, or an abort frame */

#endif
