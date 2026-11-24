/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The cFS app as an enforcement point of policy distribution (docs/design/spec-policy-distribution.md, the `cfs`
 *   kind), with no cFE in it: the C core of distribution (prismpath-hw/dist), its durable state in the app's stores,
 *   the table service as the runtime switch, and the decisions and receipts of each proposal.
 *
 * A table is admitted by its distribution envelope. The ground sends the sealed envelope and the table's bytes before
 * ImageSig in the frames of section 8.3 on the app's command topic (an offer, then chunks), and a commit or an abort
 * frame after them, the commit with the table's ImageSig, the core run's image attestation, beside it. The core
 * verifies and stages what the frames assemble (V1, G1). A commit goes through the table service before the core
 * flips: the app asks the core what the commit would answer (pp_pep_commit_check), loads the whole table with
 * CFE_TBL_Load from its address, whose validation callback holds it to the same answer and to the kernel's checks,
 * and commits only once the table service has taken it. At one `now` the core answers the commit as it answered the
 * check, since nothing runs in between, so a failed load leaves the core where it was and its active record is never
 * ahead of the table service (section 9.5). What decides is the kernel, which the core's runtime step activates from
 * the active release it holds, so a table the table service holds by another path never decides.
 *
 * What the core keeps durably is in parts (pp_durable). The anchor, the counter, the trust store with its time floor,
 * the floor of section 6 (its seq and envelope ids) and a commit's intent are in the Critical Data Store record with
 * the run, so a processor reset keeps them and a store that does not read loses them together: that is the lost floor
 * of Q5, answered as the mission chooses (LOCK by default, or MINIMUM). The releases are files, each with the image
 * attestation of its table. The install record, its rate counts and the three install sets are files, and their
 * second copies are a Critical Data Store area apart from the file (IS10).
 *
 * Every bound is a constant here or in pp_dist.h, and nothing is allocated.
 */
#ifndef PRISMPATH_APP_DIST_H
#define PRISMPATH_APP_DIST_H

#include <stddef.h>
#include <stdint.h>

#include "pp_dist.h"
#include "prismpath_app_kernel.h"
#include "prismpath_app_run.h"

#if PP_TABLE_MAX < PP_CFS_TABLE_MAX
#error "the cFS app builds the C core of distribution with -DPP_TABLE_MAX=4692, the bound of a cfs.table (CMakeLists.txt)"
#endif

/** The expiry response (X6), a platform setting the PEP is provisioned with and held to (X10). */
#define PP_EXPIRY_REFUSE 0 /**< the release lapses at expiry and every decision is refused */
#define PP_EXPIRY_HOLD   1 /**< the expired release keeps deciding, every record and receipt marked held */

/** What a store held at a start. */
enum
{
    PP_APP_STORE_ABSENT = 0, /**< none: a power on reset, or a store that was deleted */
    PP_APP_STORE_READ   = 1,
    PP_APP_STORE_LOST   = 2  /**< present and not readable */
};

/** The parts of the core kept in the Critical Data Store record, and the bytes each may take packed. */
enum
{
    PP_APP_SMALL_ANCHOR,
    PP_APP_SMALL_COUNTER,
    PP_APP_SMALL_TRUST,
    PP_APP_SMALL_FLOOR,
    PP_APP_SMALL_PENDING,
    PP_APP_SMALL_PARTS
};
#define PP_APP_SMALL_BYTES 9216 /* the five packed, the trust store's 8,372 the largest (K5, R7) */

/** The parts kept in two copies (IS10), and the bytes each may take packed. */
enum
{
    PP_APP_COPY_INSTALL,
    PP_APP_COPY_RATES,
    PP_APP_COPY_FLOOR,
    PP_APP_COPY_FALLBACK,
    PP_APP_COPY_CEILING,
    PP_APP_COPY_PARTS
};
#define PP_APP_SET_BYTES  (12 + 2 * (8 + PP_MAX_SEALED + PP_INSTALL_BODY_MAX)) /* a set, held and staged */
#define PP_APP_COPY_BYTES (1024 + 128 + 3 * PP_APP_SET_BYTES)

/** The Critical Data Store record: the run, and the core's parts the store Q5 can lose. Plain data. */
typedef struct
{
    uint32_t      Magic; /**< PP_APP_RECORD_MAGIC */
    uint32_t      Size;  /**< sizeof(PP_AppRecord_t) */
    PP_RunState_t Run;
    uint32_t      Len[PP_APP_SMALL_PARTS]; /**< 0 for a part never written */
    uint8_t       Bytes[PP_APP_SMALL_BYTES];
} PP_AppRecord_t;
#define PP_APP_RECORD_MAGIC 0x50504452u /* "PPDR" */

/** The Critical Data Store area that holds the second copy of the install parts (IS10). Plain data. */
typedef struct
{
    uint32_t Magic; /**< PP_APP_COPY_MAGIC */
    uint32_t Size;
    uint32_t Len[PP_APP_COPY_PARTS];
    uint8_t  Bytes[PP_APP_COPY_BYTES];
} PP_AppInstallCopy_t;
#define PP_APP_COPY_MAGIC 0x50504943u /* "PPIC" */

/** The app's stores and its table service. */
typedef struct
{
    void *Ctx;
    int (*SaveRecord)(void *Ctx);  /**< copy the record to the Critical Data Store, 0 when it did */
    int (*SaveCopy)(void *Ctx);    /**< copy the install copy to its area */
    int (*WriteFile)(void *Ctx, const char *Name, const void *Data, size_t Len); /**< replace a file whole */
    int32_t (*ReadFile)(void *Ctx, const char *Name, void *Data, size_t Cap);   /**< its bytes, or -1 for none */
    int (*LoadTable)(void *Ctx, const PP_PolicyTable_t *Table); /**< through the table service: 0 when it took it */
} PP_AppStore_t;

/** A sealed envelope and its body as the ground's provisioning writes them on the file system, with the table's image
 *  attestation for a release's table (integrations/cfs/ground/provision.py, `statement_file`). */
typedef struct
{
    const uint8_t *Sealed;
    size_t         SealedLen;
    const uint8_t *Body;
    size_t         BodyLen;
    int            HasImageSig;
    uint8_t        ImageSig[64];
} PP_AppStatement_t;

#define PP_APP_BROUGHT_MAX 4 /**< install statements brought with the anchor (P2 step 3) */
#define PP_APP_BOOT_MAX    2 /**< a boot release: its widening statement and its table */

/** What the app was built and provisioned with. */
typedef struct
{
    int            ExpiryResponse; /**< PP_EXPIRY_REFUSE or PP_EXPIRY_HOLD */
    int            LostFloor;      /**< PP_LOST_FLOOR_LOCK or PP_LOST_FLOOR_MINIMUM */
    long long      MinSeq;         /**< the lowest seq a MINIMUM floor admits */
    uint32_t       MonitorStale;   /**< PRISMPATH_APP_MONITOR_STALE_SECS */
    uint8_t        InstanceSeed[32];
    const uint8_t *Anchor;         /**< the trust anchor document, or NULL for none */
    size_t         AnchorLen;
    PP_AppStatement_t Brought[PP_APP_BROUGHT_MAX];
    size_t            NBrought;
    PP_AppStatement_t Boot[PP_APP_BOOT_MAX];
    size_t            NBoot;
} PP_AppDistConfig_t;

/** One step's outcome, for the app's events. */
#define PP_APP_OUTBOX 16
typedef struct
{
    size_t  N;
    size_t  Len[PP_APP_OUTBOX];
    uint8_t Record[PP_APP_OUTBOX][PP_RECORD_MAX]; /**< every state record the step made, oldest first */
    int     HoldBegan, HoldEnded;  /**< X7: the hold began or ended in this step */
    int     Provisioned;           /**< P2: the app provisioned itself from its anchor in this step */
    uint8_t Fingerprint[32];       /**< the anchor's, when provisioned */
    int     Locked;                /**< the floor was lost and the mission's response is LOCK */
    int     FloorAt;               /**< the floor was lost and the response is MINIMUM: admitted from MinSeq */
    uint8_t TableCause;            /**< the table service refused a switch with this cause (0 for none) */
    int     TableBusy;             /**< the table service refused a switch for its own reason */
    uint8_t Dropped;               /**< a transfer the frames dropped, with this cause */
} PP_AppStep_t;

/** One decision of a proposal. */
typedef struct
{
    uint8_t  Kind;      /**< PP_KIND_*: what the app acts on */
    uint16_t Cause;     /**< the registered cause of a refusal or an escalation */
    int16_t  Rule;      /**< the rule that decided, or -1 */
    int16_t  Field;     /**< the field the boundary refused, or -1 */
    uint8_t  Basis;     /**< PP_BASIS_* of the decision (RC1) */
    int      Held;      /**< decided while held (X7) */
    int      Receipted; /**< a receipt was written, at Receipt */
    uint64_t Receipt;
    int      NotEnacted;   /**< the action floor or the fallback policy decided, which a core run cannot carry yet */
    int      RecordError;  /**< the decision could not be receipted, so an allow is not carried out */
} PP_AppDecision_t;

/** The app's enforcement point. One per app, in static storage. */
typedef struct
{
    PP_AppStore_t       Store;
    PP_AppRecord_t      Record; /**< the Critical Data Store record, kept as the store holds it */
    PP_AppInstallCopy_t Copy;
    PP_RunKeys_t        Keys;
    pp_pep_machine      Pep;
    pp_config           Config;
    pp_layout           Layout;
    pp_assembler        Assembler;
    int                 Started;  /**< 0 when the core refused to start (X10, K2): nothing is admitted or decided */
    PP_PolicyTable_t    Active;   /**< the table the kernel decides with, its digest and image attestation */
    uint8_t             ActiveDigest[32];
    uint8_t             ActiveSig[64], PreviousSig[64]; /**< the image attestations of the active and kept tables */
    int                 Switching;  /**< 1 for a commit, 2 for a rollback, while the core flips */
    uint8_t             NextActiveSig[64], NextPreviousSig[64];
    int                 Pending;    /**< 1: a switch is in the table service, which its validation admits; 2: the
                                         active table shown again */
    PP_PolicyTable_t    PendingTable;
    int                 PendingRollback;
    char                PendingStream[PP_STREAM_MAX + 1];
    long long           PendingSeq;
    uint8_t             PendingPolicy[32];
    long long           Now;
    int                 Due;        /**< B8: a commit waiting for its delay */
    uint32_t            DueMs;
    uint8_t             DueFrame[46];
    uint8_t             DueSig[64];
    int                 WasHeld;
    PP_AppStep_t        Step;
} PP_AppDist_t;

/**
 * Start the enforcement point. Record and Copy are what the two Critical Data Store areas held, with what each was
 * (PP_APP_STORE_*), already copied into D->Record and D->Copy by the caller. A record that is absent is a first start
 * or a power on reset: a new run begins and the app provisions itself from its anchor and the statements brought
 * with it (P2, P4). A record that is lost loses the floor: under PP_LOST_FLOOR_LOCK the core is locked until ground
 * deletes the store and restarts the app, and under PP_LOST_FLOOR_MINIMUM the app provisions itself again from its
 * anchor with the floor one below MinSeq. A record that reads restores the run and the core. When no release is
 * active the boot release is staged and committed as if offered. Returns 0, or -1 when the core refused to start.
 */
int PP_AppDist_Start(PP_AppDist_t *D, const PP_AppDistConfig_t *Cfg, int Record, int Copy, uint32_t NowMs,
                     long long Now);

/** One frame of an offer or a chunk from the command topic, at the app's monotonic time and its time. */
void PP_AppDist_Frame(PP_AppDist_t *D, const uint8_t *Frame, size_t Len, uint32_t NowMs, long long Now);

/** A commit or an abort frame, the commit with the table's image attestation. */
void PP_AppDist_Control(PP_AppDist_t *D, const uint8_t *Frame, size_t Len, const uint8_t ImageSig[64], uint32_t NowMs,
                        long long Now);

/** X1, B8: the expiry check, and a commit whose delay has passed. */
void PP_AppDist_Tick(PP_AppDist_t *D, uint32_t NowMs, long long Now);

/** RB1: the local rollback, through the table service as a commit is. */
void PP_AppDist_Rollback(PP_AppDist_t *D, long long Now);

/** A state record of the PEP as it is now (a beat for housekeeping). */
void PP_AppDist_Beat(PP_AppDist_t *D, long long Now);

/** The table service's validation of a table being loaded: 0 when it is the switch the app is making, the kernel
 *  passes it and the core still answers the switch as it did, else the cause. A table loaded by any other path, such
 *  as a ground table load from a file, has no envelope and is refused with dist:not-staged. */
int PP_AppDist_ValidateTable(PP_AppDist_t *D, const PP_PolicyTable_t *Table);

/**
 * Decide one proposal: the boundary first, then the core asks the action floor and the active release or the
 * fallback policy (AF1, FB1), and the kernel decides a release decision, which is receipted (with the hold mark of
 * X7 in its case) before it is acted on. MonitorAge is the age in seconds of the monitor's last verdict, or
 * PP_AGE_NONE. A decision of the action floor or of the fallback policy is refused and not enacted, since its case
 * would be attested by an install statement, which the core run's verifier does not read yet (RC4).
 */
void PP_AppDist_Propose(PP_AppDist_t *D, const PP_RunIo_t *Io, const uint8_t *Payload, size_t PayloadLen,
                        uint32_t MonitorAge, long long Now, PP_AppDecision_t *Out);

/** Load the table that decides now through the table service, after a start, so it shows what the kernel holds. */
int PP_AppDist_LoadActive(PP_AppDist_t *D);

/** Save the record after the run changed (a receipt, a seal). 0 when the store took it. */
int PP_AppDist_SaveRun(PP_AppDist_t *D);

/** The parts' file names, under the app's distribution directory. */
extern const char *const PP_AppDistFiles[3 + PP_APP_COPY_PARTS];

/** Read a statement file of the ground's provisioning (`statement_file`) in place: 0, or -1 when it is not one. */
int PP_AppDist_ReadStatement(const uint8_t *Data, size_t Len, PP_AppStatement_t *Out);

#endif
