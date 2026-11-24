/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The app's receipts, as a signed core run (docs/design/spec-verified-core.md section 11), with no cFE in it.
 *
 * Every decision under an active image is a `prismpath.core-receipt/1` line, the exact bytes the ground's
 * verifier (prismpath/ledgers/core_evidence.py) holds a receipt to: the image's SHA-256 is that of the signed
 * core image the table carries, the reading's is that of the reading's canon/2 bytes, which this module writes
 * from the payload the way the reference reads it (the fields the payload holds, in register order, a bool as
 * false or true when it is 0 or 1 and as its number otherwise). The SHA-256 of each line is a leaf of the RFC
 * 6962 Merkle tree, kept in its streaming form (prismpath-ebpf/merkle.h, `struct ppt_merkle_acc`, whose root is
 * the tree's by formal/Core/Merkle.lean `acc_root_eq_mth`).
 *
 * The run directory it writes is the core run layout itself (one file name aside, below), so the ground runs
 * `prismpath evidence verify` on it as downlinked:
 *
 *   receipts.jsonl        one receipt per decision, appended before an allowed command is republished
 *   cases.stream          cases.jsonl as it grows: one case per image the app decided under, its line
 *                         open while the image is active (the readings are appended as they are decided)
 *   images.jsonl          one image attestation per case, the authority's signature from the table
 *   cases.jsonl, run.json, roots.jsonl, authority.pub, instance.pub
 *                         written by a seal: the closed cases file, the manifest, and one
 *                         `prismpath.core-run-root/2` statement over every receipt, signed onboard with the
 *                         instance key (Ed25519, Monocypher as prismpath-hw/mesh vendors it); the core run
 *                         calls the statement's file receipts.roots.jsonl, one character past OSAL's file name
 *                         limit, so the ground's copy renames it (integrations/cfs/ground/downlink.py)
 *   roots.log.jsonl       every root statement sealed so far, one per line: the history that shows a root
 *                         taken before a processor reset is the root of a prefix of the leaves after it
 *
 * The state that must survive a processor reset is PP_RunState_t, which the app keeps in the Critical Data
 * Store: the highest accepted image version and its table digest, the accumulator's peaks and count, the open
 * case, and the length of every appended file (a file longer than its recorded length after a reset is cut
 * back, since the reset came between the write and the store's update).
 *
 * Files are reached through PP_RunIo_t, so the app gives OSAL's calls and a host test gives stdio's.
 */
#ifndef PRISMPATH_APP_RUN_H
#define PRISMPATH_APP_RUN_H

#include <stddef.h>
#include <stdint.h>

#define PPT_MERKLE_NO_RECEIPTS
#include "merkle.h"
#include "prismpath_app_kernel.h"

/** Who decided, in every receipt and the manifest. Another framework's build names itself by defining this
 *  (integrations/fprime does), and nothing else in a receipt then differs. */
#ifndef PP_RUN_DECIDER
#define PP_RUN_DECIDER "cfs:prismpath_app"
#endif

/** The state the Critical Data Store keeps. Plain data: it is copied in and out of the store whole. */
typedef struct
{
    uint32_t              Magic;        /**< PP_RUN_MAGIC */
    uint32_t              Size;         /**< sizeof(PP_RunState_t), so a store from another build is not read */
    uint32_t              FloorVersion; /**< the highest image version accepted, 0 before the first */
    uint32_t              CaseOpen;     /**< 1 while a case's line is open in cases.stream */
    uint8_t               FloorDigest[32];
    uint32_t              CaseCount;    /**< cases opened */
    uint32_t              CaseVersion;  /**< the open case's image version (its case id is v<version>) */
    uint8_t               CaseDigest[32];
    uint32_t              CaseReadings; /**< readings decided in the open case */
    uint32_t              FloorLost;    /**< 1 when the floor was lost and the response is PP_LOST_FLOOR_LOCK */
    uint64_t              ReceiptsLen;  /**< bytes of receipts.jsonl, cases.stream and images.jsonl written */
    uint64_t              StreamLen;
    uint64_t              ImagesLen;
    uint64_t              Seals;        /**< root statements signed */
    uint32_t              CaseHold;     /**< 1 when the open case holds decisions made while held (X7) */
    uint32_t              CaseNumber;   /**< 0, or the open case's number when its id is v<version>.<number> */
    uint32_t              CaseMaxVersion; /**< the highest version a case of this run had */
    uint32_t              Spare;
    struct ppt_merkle_acc Acc;          /**< the receipts' peaks and count */
} PP_RunState_t;

#define PP_RUN_MAGIC 0x50505253u /* "PPRS" */

/** What a new run admits when the Critical Data Store held a state that did not read, so the version floor is lost
 *  (PP_Run_LoseFloor). The mission chooses by PRISMPATH_APP_PLATFORM_LOST_FLOOR. */
#define PP_LOST_FLOOR_LOCK    0 /**< no image, so every proposal is refused, until ground deletes the store */
#define PP_LOST_FLOOR_MINIMUM 1 /**< every image from the mission's minimum version up */

/** The run's files, by index. */
enum
{
    PP_FILE_RECEIPTS = 0,
    PP_FILE_STREAM,
    PP_FILE_IMAGES,
    PP_FILE_CASES,
    PP_FILE_RUN,
    PP_FILE_ROOTS,
    PP_FILE_ROOTLOG,
    PP_FILE_AUTHORITY,
    PP_FILE_INSTANCE,
    PP_FILE_COUNT
};

/** Open modes. */
enum
{
    PP_IO_READ   = 0,
    PP_IO_APPEND = 1, /**< write at the end, creating the file when absent */
    PP_IO_CREATE = 2  /**< write from empty, replacing the file */
};

/** File access. Open returns a handle >= 0 or < 0; Write returns 0 when every byte was written; Read returns
 *  the bytes read (0 at the end) or < 0; Size returns the file's length or < 0 when it is absent; Truncate cuts a
 *  file to Len bytes and returns 0. */
typedef struct
{
    void *Ctx;
    int32_t (*Open)(void *Ctx, int File, int Mode);
    int32_t (*Write)(void *Ctx, int32_t Handle, const void *Buf, size_t Len);
    int32_t (*Read)(void *Ctx, int32_t Handle, void *Buf, size_t Len);
    void (*Close)(void *Ctx, int32_t Handle);
    int64_t (*Size)(void *Ctx, int File);
    int32_t (*Truncate)(void *Ctx, int File, uint64_t Len);
} PP_RunIo_t;

/** The keys onboard: the authority's public key (which images may run) and the instance key pair (which signs
 *  what the app recorded). HaveInstance is 0 when no instance key was provisioned: decisions are receipted, and a
 *  seal says it cannot sign. */
typedef struct
{
    uint8_t AuthorityPub[32];
    uint8_t InstanceSecret[64]; /**< Monocypher's form: the seed then the public key */
    uint8_t InstancePub[32];
    int     HaveAuthority;
    int     HaveInstance;
} PP_RunKeys_t;

/** The file names, in PP_FILE_ order. */
extern const char *const PP_RunFileNames[PP_FILE_COUNT];

/** A fresh state: no floor, no receipts, no case. */
void PP_Run_Init(PP_RunState_t *State);

/** 1 when State reads as this build's state with its counts consistent, else 0. */
int PP_Run_StateValid(const PP_RunState_t *State);

/** Load the instance key pair from its 32 byte seed (the seed is wiped). */
void PP_Run_SetInstanceSeed(PP_RunKeys_t *Keys, uint8_t Seed[32]);

/**
 * The checks of a table the cFS app admits by its distribution envelope (docs/design/spec-policy-distribution.md,
 * section 3), beyond the kernel's and the envelope's own, which the C core of distribution makes: the core image and
 * the flow are within the table and the causes the core refuses with are ones a receipt can name (69 otherwise), the
 * table's bytes before ImageSig are the body the envelope signed, whose SHA-256 is BodySha256 (dist:body-mismatch 138),
 * and the image attestation verifies under the run's authority key (sig:missing 1, sig:invalid 2), so the run's
 * images.jsonl stays verifiable. ImageSig is the core run's attestation and no longer what admits a table. Returns 0
 * or that cause, and the table's digest (the body's SHA-256) in Digest.
 */
int PP_Run_CheckTable(const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Table, const uint8_t BodySha256[32],
                      uint8_t Digest[32]);

/**
 * The checks of a table admitted by the authority's two signatures alone, as a framework with no distribution envelope
 * admits one (integrations/fprime): the bounds above, the authority key provisioned (sig:missing 1), the table
 * signature and the image attestation (sig:invalid 2), and the version not below the floor, nor equal to it with
 * another table (image:version-replay 9). Returns 0 or that cause, and the digest the table signature covers.
 */
int PP_Run_CheckSignedTable(const PP_RunState_t *State, const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Table,
                            uint8_t Digest[32]);

/** Raise the floor of PP_Run_CheckSignedTable to an accepted table's version and digest. */
void PP_Run_Accept(PP_RunState_t *State, uint32_t Version, const uint8_t Digest[32]);

/** Begin the floor of a new run whose store held a state that did not read (call after PP_Run_Init). Under
 *  PP_LOST_FLOOR_LOCK the state is marked so that PP_Run_CheckTable refuses every table with the replay cause, and
 *  the mark is saved with the state, so a later reset keeps it; only a new store (ground deletes it and restarts the
 *  app) clears it. Under PP_LOST_FLOOR_MINIMUM the floor admits every image of MinVersion and up. */
void PP_Run_LoseFloor(PP_RunState_t *State, int Response, uint32_t MinVersion);

/**
 * Record one decision under the active table: open its case when it is not the open one (closing the one before),
 * append the reading to the case and the receipt to receipts.jsonl, and add the receipt's leaf. Hold is 1 for a
 * decision made while the app is held past its release's expiry (X7): a hold opens a new case, and its end another,
 * and such a case's line carries "hold":true, so each receipt keeps its format and its case says it was held.
 * Returns 0, or -1 when a file could not be written, in which case the state is unchanged and the caller must not
 * act on the decision. On success Index is the receipt's index.
 */
int PP_Run_Record(PP_RunState_t *State, const PP_RunIo_t *Io, const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Active,
                  const uint8_t ActiveDigest[32], const uint8_t *Payload, size_t PayloadLen, const PP_Verdict_t *Verdict,
                  int Hold, uint64_t *Index);

/**
 * Seal the run: write cases.jsonl (the stream, its open case closed), run.json, receipts.roots.jsonl with one
 * statement signed with the instance key, the two public keys, and append the statement to roots.log.jsonl.
 * TimeUs is the statement's time. Returns 0, -2 when no instance or authority key is loaded, -1 when a document
 * does not fit its buffer, or PP_SEAL_FILE_ERR(file) for the file that could not be read or written.
 */
#define PP_SEAL_FILE_ERR(File) (-10 - (File))
int PP_Run_Seal(PP_RunState_t *State, const PP_RunIo_t *Io, const PP_RunKeys_t *Keys, uint64_t TimeUs);

/**
 * After a processor reset: hold every appended file to the length the state recorded. A longer file is cut back
 * (the reset came after its write and before the store's update). Returns 0, or -1 when a file is shorter than
 * recorded or cannot be cut, which leaves a run the ground will refuse.
 */
int PP_Run_Recover(const PP_RunState_t *State, const PP_RunIo_t *Io);

/** Start the appended files empty, for a fresh state (a power on reset). Returns 0 or -1. */
int PP_Run_Begin(const PP_RunIo_t *Io);

/** The root over the receipts so far (32 zero bytes when there are none); returns the count. */
uint64_t PP_Run_Root(const PP_RunState_t *State, uint8_t Root[32]);

/**
 * The reading's canon/2 bytes for a payload, as the reference reads it. Returns the length written into Out, or
 * 0 when Cap is too small.
 */
size_t PP_Run_ReadingBytes(const uint8_t *Payload, size_t PayloadLen, char *Out, size_t Cap);

/** The receipt line for one decision (no line feed). Returns the length, or 0 when Cap is too small or the
 *  verdict names a cause the receipt cannot spell. */
size_t PP_Run_ReceiptBytes(uint64_t Index, uint32_t CaseVersion, uint32_t CaseNumber, uint32_t Reading,
                           const uint8_t ImageSha[32],
                           const uint8_t ReadingSha[32], const PP_Verdict_t *Verdict, const PP_PolicyTable_t *Active,
                           char *Out, size_t Cap);

#endif
