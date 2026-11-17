/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The F Prime guard's C core: the glue between the component and the decision and receipt code the cFS app
 *   uses (integrations/cfs/prismpath_app/fsw/src/prismpath_app_kernel.c and prismpath_app_run.c, compiled in
 *   place). It is the counterpart of prismpath_app.c's table, proposal and seal handling, with no cFE and no F
 *   Prime in it, so the component's C++ never includes the kernel's headers.
 */
#ifndef PRISMPATH_GUARD_CORE_H
#define PRISMPATH_GUARD_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct GC GC;

enum
{
    GC_ALLOW        = 0,
    GC_REFUSE       = 1,
    GC_ESCALATE     = 2,
    GC_RECORD_ERROR = 3 /**< the decision could not be receipted, so it is not acted on */
};

typedef struct
{
    int      Kind;       /**< GC_ALLOW, GC_REFUSE, GC_ESCALATE or GC_RECORD_ERROR */
    int      Rule;       /**< the matched rule, -1 when the core itself refused or no image decided */
    unsigned Cause;      /**< registered cause code of a refusal or escalation */
    char     Field[17];  /**< the field the boundary refused, else empty */
    int64_t  Receipt;    /**< the receipt's index, -1 when none was written */
} GC_Outcome;

GC *GC_Create(void);
void GC_Destroy(GC *Core);

/**
 * Read the signed policy table (the raw bytes of PP_PolicyTable_t; a cFE table file with its 116 byte headers is
 * accepted too), the authority's public key (KeysDir/pp_authority.pub) and the instance seed (KeysDir/
 * pp_instance.key), check the table as the cFS app does and activate it. The first call begins the run in
 * RunDir. Returns 0 (Version and Rules filled), a registered cause code > 0 when the table is refused, or -1
 * when a file could not be read (What names it).
 */
int GC_Load(GC *Core, const char *PolicyFile, const char *KeysDir, const char *RunDir, uint32_t *Version,
            uint32_t *Rules, char What[64]);

/**
 * Decide a proposed command's serialized argument bytes (big endian, in the layout's register order) and receipt
 * the decision before it is acted on. Returns 0.
 */
int GC_Propose(GC *Core, const uint8_t *Args, size_t Len, GC_Outcome *Out);

/** Seal the run at TimeUs. Returns 0, or what PP_Run_Seal returns. Leaves and the root (64 hex digits) filled. */
int GC_Seal(GC *Core, uint64_t TimeUs, uint32_t *Leaves, char Root[65]);

/** The receipt count, and 1 when a policy is active. */
uint32_t GC_Receipts(const GC *Core);
int      GC_Active(const GC *Core);

#ifdef __cplusplus
}
#endif

#endif
