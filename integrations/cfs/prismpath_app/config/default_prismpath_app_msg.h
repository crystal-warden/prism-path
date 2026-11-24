/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   PRISMPATH_APP message and table types: the ground commands, the proposed and vehicle commands, the
 *   housekeeping telemetry and the policy table. */
#ifndef DEFAULT_PRISMPATH_APP_MSG_H
#define DEFAULT_PRISMPATH_APP_MSG_H

#include <stddef.h>
#include "common_types.h"
#include "cfe_msg_hdr.h"
#include "prismpath_app_fcncodes.h"
#include "prismpath_app_layout.h"
#include "prismpath_app_kernel.h"

typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
} PRISMPATH_APP_NoArgsCmd_t;

typedef PRISMPATH_APP_NoArgsCmd_t PRISMPATH_APP_NoopCmd_t;
typedef PRISMPATH_APP_NoArgsCmd_t PRISMPATH_APP_ResetCountersCmd_t;
typedef PRISMPATH_APP_NoArgsCmd_t PRISMPATH_APP_SendHkCmd_t;
typedef PRISMPATH_APP_NoArgsCmd_t PRISMPATH_APP_SealCmd_t;


/**
 * A proposed command, and the allowed command republished on the vehicle message id: the same payload. The
 * payload bytes are the reading, laid out as prismpath_app_layout.h says (little endian).
 */
typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
    uint8                   CmdClass;      /**< 1 attitude, 2 thruster, 3 payload; anything else is refused */
    uint8                   GroundContact; /**< 1 when a ground contact is open, else 0 */
    uint16                  SlewDeg;       /**< attitude slew, degrees */
    uint16                  ThrustPct;     /**< thruster burn, percent */
    uint8                   MonitorOk;     /**< the monitor's verdict: written by the PrismPath app, never read from a proposer */
    uint8                   Pad;
    uint16                  Spare;
} PRISMPATH_APP_ProposedCmd_t;

/** The largest frame of the frame binding a command carries (docs/design/spec-policy-distribution.md section 8.3,
 *  the limit of the link, which is also ESP-NOW's). */
#define PRISMPATH_APP_FRAME_MAX 250

/**
 * One frame of policy distribution on the command topic: an offer or a chunk (PRISMPATH_APP_OFFER_CC,
 * PRISMPATH_APP_CHUNK_CC), FrameLen bytes of Frame in use. The ground sends a table's sealed envelope and its body,
 * the table's bytes before ImageSig, as integrations/cfs/ground/table.py frames them.
 */
typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
    uint16                  FrameLen;
    uint16                  Spare;
    uint8                   Frame[PRISMPATH_APP_FRAME_MAX];
} PRISMPATH_APP_FrameCmd_t;

/** A commit or an abort frame (PRISMPATH_APP_CONTROL_CC), a commit with the table's image attestation: the ImageSig the
 *  table carries for the core run's images.jsonl, which the body before it does not hold. */
typedef struct
{
    CFE_MSG_CommandHeader_t CommandHeader;
    uint16                  FrameLen;
    uint16                  Spare;
    uint8                   Frame[PRISMPATH_APP_FRAME_MAX];
    uint8                   ImageSig[64];
} PRISMPATH_APP_ControlCmd_t;

/**
 * The runtime monitor's verdict, published by the monitor once a second on PRISMPATH_APP_MONITOR_VERDICT_MID. Ok is
 * 1 while the monitored property holds. The PrismPath app keeps the latest one and the time it arrived, and reads
 * it as the policy's monitor_ok field only while it is ok and no older than the staleness bound.
 */
typedef struct
{
    CFE_MSG_TelemetryHeader_t TelemetryHeader;
    uint8                     Ok;
    uint8                     Spare8;
    uint16                    Spare16;
    uint32                    Step;        /**< the monitor's step count, for the ground's logs */
} PRISMPATH_APP_MonitorVerdict_t;

typedef struct
{
    uint8  CommandCounter;
    uint8  CommandErrorCounter;
    uint8  PolicyActive;       /**< 1 when an image passed the kernel's checks and is the one deciding */
    uint8  Spare;
    uint32 PolicyLayoutHash;
    uint32 Proposed;           /**< proposals received */
    uint32 Allowed;
    uint32 Refused;
    uint32 Escalated;
    uint32 Forwarded;          /**< allowed commands accepted by the software bus */
    uint32 ForwardErrors;
    uint32 PoliciesLoaded;     /**< images activated, the first load included */
    uint32 PoliciesRejected;   /**< images the kernel's checks refused */
    uint32 LastRefusalCause;   /**< registered cause of the latest refusal or escalation, 0 if none */
    uint32 ReceiptCount;       /**< receipts in the run: the Merkle tree's leaf count, continued across resets */
    uint32 Unreceipted;        /**< decisions with no image active, refused and not receipted (no image to bind) */
    uint32 RecordErrors;       /**< decisions that could not be receipted (an allowed one was withheld) */
    uint32 PolicyVersion;      /**< the image version of the active table, 0 for none */
    uint32 Seals;              /**< root statements signed onboard */
    uint8  Root[16];           /**< the first 16 bytes of the current Merkle root (the full root is in the run's files) */
    uint32 NotEnacted;         /**< decisions of the action floor or the fallback policy, refused and not receipted */
    uint32 FramesDropped;      /**< distribution frames dropped (dist:frame-invalid, dist:too-large, a refused envelope) */
    uint16 StateRecordLen;     /**< bytes of StateRecord in use */
    uint16 Spare16;
    /** A state record of policy distribution (H1), signed by the instance key: the latest the app made, or a beat at
     *  this housekeeping request. Bit 5 of its status byte is set while the app is held past its release's expiry. */
    uint8  StateRecord[244];
} PRISMPATH_APP_HkTlm_Payload_t;

typedef struct
{
    CFE_MSG_TelemetryHeader_t     TelemetryHeader;
    PRISMPATH_APP_HkTlm_Payload_t Payload;
} PRISMPATH_APP_HkTlm_t;

/** The policy table: the kernel's own table type. */
typedef PP_PolicyTable_t PRISMPATH_APP_PolicyTable_t;

#endif
