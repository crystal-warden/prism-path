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

/** The policy table: the cFE table's content. Fixed size, little endian image bytes (PPT v1). */
typedef struct
{
    uint32_t  LayoutHash;    /**< hash of the field layout the image was compiled for */
    uint16_t  ImageLen;      /**< bytes of Image in use */
    uint16_t  RuleCount;     /**< rules in use; the image's one node has this many edges */
    uint16_t  ContractCause; /**< registered cause of a reading outside its field definitions */
    uint16_t  NoMatchCause;  /**< registered cause of a reading no rule holds */
    PP_Rule_t Rules[PRISMPATH_APP_MAX_RULES];
    uint8_t   Image[PRISMPATH_APP_IMAGE_MAX];
} PP_PolicyTable_t;

/** One decision. Rule is the matched edge, or -1 when the core itself refused. Field is the register of the
 *  field outside its bounds for a boundary refusal, or -1. */
typedef struct
{
    uint8_t  Kind;
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
 * Decide one proposed command. Payload is the bytes after the command header. A payload shorter than the
 * layout needs, or a field outside its bounds, is the core's boundary refusal. With no active image the
 * answer is a refusal with PP_NO_IMAGE_CAUSE. Bounded work: one pass over the image's rules, no allocation.
 */
void PP_Kernel_Decide(const uint8_t *Payload, size_t PayloadLen, PP_Verdict_t *Verdict);

/** The name of the field at a register, for the event text. */
const char *PP_Kernel_FieldName(int16_t Field);

#endif
