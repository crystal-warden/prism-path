/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The decision core of the PrismPath cFS app, with no cFE in it.
 *
 * It wraps PrismPath's embedded evaluator (prismpath-hw/ppt_eval.h, the one copy every firmware includes) and
 * adds the three things an app needs around it: the structural checks that make an image safe to run, the
 * reading boundary (field widths and bounds), and the mapping from the matched edge to the rule's action.
 * Everything is static storage. Nothing here allocates, and the only file that includes ppt_eval.h is
 * prismpath_app_kernel.c, because that header keeps its table in file scope statics.
 */
#ifndef PRISMPATH_APP_KERNEL_H
#define PRISMPATH_APP_KERNEL_H

#include <stddef.h>
#include <stdint.h>

#define PRISMPATH_APP_IMAGE_MAX 1024 /**< bytes of image a table holds */
#define PRISMPATH_APP_MAX_RULES 16   /**< rules (edges of the policy's one node) a table holds */
#define PRISMPATH_APP_CORE_MAX  2048 /**< bytes of the signed core image (canon/2) a table holds */
#define PRISMPATH_APP_FLOW_MAX  1536 /**< bytes of the flow's canon/2 string a table holds */

enum
{
    PP_KIND_ALLOW    = 0,
    PP_KIND_REFUSE   = 1,
    PP_KIND_ESCALATE = 2
};

/** What a rule does, and for a refusal or an escalation the registered cause code it carries. */
typedef struct
{
    uint8_t  Kind;
    uint8_t  Spare;
    uint16_t Cause;
} PP_Rule_t;

/**
 * The policy table: the cFE table's content. Fixed size, every member at its natural alignment so the struct has
 * no padding (the table signature covers its bytes). The first six members and Rules and Image are what the
 * kernel decides with (PPT v1 image bytes, little endian). The rest is S2's:
 *
 *   Version   the image's version, which the Critical Data Store holds a floor for: a table whose version is
 *             below the highest accepted one, or equal to it with other bytes, is refused (image:version-replay)
 *   Core      the signed core image (prismpath.core/1, canon/2 bytes) the PPT image was compiled from: what a
 *             receipt's image_sha256 hashes and what the ground's verifier replays
 *   FlowJson  the core image's canonical flow rendering, already spelled as a canon/2 string (quotes included),
 *             which a core run's cases file carries beside the image
 *   ImageSig  the authority's Ed25519 signature over "prismpath.core-image/1\0" and Core: the core run's image
 *             attestation, checked here and copied to images.jsonl
 *   TableSig  the authority's Ed25519 signature over "prismpath.cfs-table/1\0" and the SHA-256 of every byte of
 *             this struct before ImageSig: it binds the version, the PPT image, the rules and the core image to
 *             each other, so neither the version nor a compiled threshold can be changed without the authority
 */
typedef struct
{
    uint32_t  LayoutHash;    /**< hash of the field layout the image was compiled for */
    uint16_t  ImageLen;      /**< bytes of Image in use */
    uint16_t  RuleCount;     /**< rules in use; the image's one node has this many edges */
    uint16_t  ContractCause; /**< registered cause of a reading outside its field definitions */
    uint16_t  NoMatchCause;  /**< registered cause of a reading no rule holds */
    uint32_t  Version;       /**< the image version the floor in the Critical Data Store is held against */
    uint16_t  CoreLen;       /**< bytes of Core in use */
    uint16_t  FlowJsonLen;   /**< bytes of FlowJson in use */
    PP_Rule_t Rules[PRISMPATH_APP_MAX_RULES];
    uint8_t   Image[PRISMPATH_APP_IMAGE_MAX];
    uint8_t   Core[PRISMPATH_APP_CORE_MAX];
    uint8_t   FlowJson[PRISMPATH_APP_FLOW_MAX];
    uint8_t   ImageSig[64];
    uint8_t   TableSig[64];
} PP_PolicyTable_t;

/** Why the core refused a reading at its boundary: the reason the reference names on its receipt. */
enum
{
    PP_REASON_NONE         = 0,
    PP_REASON_MISSING      = 1, /**< "missing": the payload ends before the field */
    PP_REASON_WRONG_TYPE   = 2, /**< "wrong_type": a bool field that is neither 0 nor 1 */
    PP_REASON_OUT_OF_RANGE = 3  /**< "out_of_range": an int field outside its definition's bounds */
};

/** One decision. Rule is the matched edge, or -1 when the core itself refused. Field is the register of the
 *  first field (in register order, the reference's order) the boundary refused, or -1, and Reason says why. */
typedef struct
{
    uint8_t  Kind;
    uint8_t  Reason;
    uint16_t Cause;
    int16_t  Rule;
    int16_t  Field;
} PP_Verdict_t;

/** The refusal cause when no image is active. The registry's route:no-matching-edge: no rule allows. */
#define PP_NO_IMAGE_CAUSE 32

/** The layout hash this build computes from prismpath_app_layout.h (FNV-1a 32 over the layout text). */
uint32_t PP_Kernel_LayoutHash(void);

/**
 * Check a table without activating it. Returns 0 when the table is safe to run, or the registered cause code
 * of the first check it fails (image:bad-magic 70, image:length-mismatch 73, image:caps-exceeded 16,
 * image:unknown-op 74, image:unknown-type 75, image:field-index-oob 76, image:edge-target-oob 77,
 * image:edge-prog-oob 78, image:atom-index-oob 80, image:unknown-opcode 79 (also a program whose operators
 * lack operands), and 69 when the table's own header is short or its rules do not match its edges).
 * The active image, if any, is left exactly as it was.
 */
int PP_Kernel_Check(const PP_PolicyTable_t *Table);

/** Check, and on success make the table the active image. On failure the active image is unchanged.
 *  Returns what PP_Kernel_Check returns. */
int PP_Kernel_Activate(const PP_PolicyTable_t *Table);

/** True once an image has been activated. */
int PP_Kernel_Active(void);

/**
 * Decide one proposed command. Payload is the bytes after the command header. A field the payload ends before
 * (missing), a bool field that is not 0 or 1 (wrong type) or an int field outside its bounds (out of range) is
 * the core's boundary refusal, for the first such field in register order, as the reference refuses the same
 * reading (prismpath_app_run.h writes that reading's canon/2 bytes). With no active image the
 * answer is a refusal with PP_NO_IMAGE_CAUSE. Bounded work: one pass over the image's rules, no allocation.
 */
void PP_Kernel_Decide(const uint8_t *Payload, size_t PayloadLen, PP_Verdict_t *Verdict);

/** The name of the field at a register, for the event text and the receipt. */
const char *PP_Kernel_FieldName(int16_t Field);

/** The reading the reference decides for a payload, one field at a time: whether the payload holds field
 *  Field (0 when it ends before it), and if so its value and whether it is a bool field. */
int PP_Kernel_FieldValue(const uint8_t *Payload, size_t PayloadLen, int Field, int32_t *Value, int *IsBool);

#endif
