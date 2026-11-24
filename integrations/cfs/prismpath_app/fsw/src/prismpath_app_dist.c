/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The cFS app as an enforcement point of policy distribution. See prismpath_app_dist.h.
 *
 * Storage is static or the caller's PP_AppDist_t. Nothing is allocated.
 */
#include <stddef.h>
#include <string.h>

#include "prismpath_app_dist.h"
#include "prismpath_app_layout.h"

/* the cfs.table the core reads is this struct's bytes before ImageSig, member for member */
_Static_assert(offsetof(PP_PolicyTable_t, ImageSig) == PP_CFS_TABLE_MAX, "a cfs.table body is the table before ImageSig");
_Static_assert(offsetof(PP_PolicyTable_t, ImageLen) == PP_CFS_OFF_IMAGE_LEN, "ImageLen");
_Static_assert(offsetof(PP_PolicyTable_t, RuleCount) == PP_CFS_OFF_RULE_COUNT, "RuleCount");
_Static_assert(offsetof(PP_PolicyTable_t, ContractCause) == PP_CFS_OFF_CONTRACT, "ContractCause");
_Static_assert(offsetof(PP_PolicyTable_t, NoMatchCause) == PP_CFS_OFF_NOMATCH, "NoMatchCause");
_Static_assert(offsetof(PP_PolicyTable_t, Version) == PP_CFS_OFF_VERSION, "Version");
_Static_assert(offsetof(PP_PolicyTable_t, CoreLen) == PP_CFS_OFF_CORE_LEN, "CoreLen");
_Static_assert(offsetof(PP_PolicyTable_t, FlowJsonLen) == PP_CFS_OFF_FLOW_LEN, "FlowJsonLen");
_Static_assert(offsetof(PP_PolicyTable_t, Rules) == PP_CFS_OFF_RULES, "Rules");
_Static_assert(offsetof(PP_PolicyTable_t, Image) == PP_CFS_OFF_IMAGE, "Image");
_Static_assert(offsetof(PP_PolicyTable_t, Core) == PP_CFS_OFF_CORE, "Core");
_Static_assert(offsetof(PP_PolicyTable_t, FlowJson) == PP_CFS_OFF_FLOW, "FlowJson");
_Static_assert(PRISMPATH_APP_MAX_RULES == PP_CFS_RULES_MAX && PRISMPATH_APP_IMAGE_MAX == PP_CFS_IMAGE_MAX &&
                   PRISMPATH_APP_CORE_MAX == PP_CFS_CORE_MAX && PRISMPATH_APP_FLOW_MAX == PP_CFS_FLOW_MAX,
               "the table's bounds are the core's");
_Static_assert(PRISMPATH_APP_FIELD_COUNT <= PP_LAYOUT_FIELDS, "the layout fits the core's");

/* OSAL limits a file name to 19 characters */
const char *const PP_AppDistFiles[3 + PP_APP_COPY_PARTS] = {
    "active.ppd", "previous.ppd", "staged.ppd", "install.ppd", "rates.ppd", "floor.ppd", "fallback.ppd", "ceiling.ppd",
};

static const int    k_SmallPart[PP_APP_SMALL_PARTS] = {PP_PART_ANCHOR, PP_PART_COUNTER, PP_PART_TRUST, PP_PART_FLOOR,
                                                       PP_PART_PENDING};
static const size_t k_SmallCap[PP_APP_SMALL_PARTS]  = {256, 64, 8576, 192, 128};
static const int    k_FilePart[3] = {PP_PART_ACTIVE, PP_PART_PREVIOUS, PP_PART_STAGED};
static const int    k_CopyPart[PP_APP_COPY_PARTS] = {PP_PART_INSTALL, PP_PART_RATES, PP_PART_SET_FLOOR,
                                                     PP_PART_SET_FALLBACK, PP_PART_SET_CEILING};
static const size_t k_CopyCap[PP_APP_COPY_PARTS] = {1024, 128, PP_APP_SET_BYTES, PP_APP_SET_BYTES, PP_APP_SET_BYTES};
_Static_assert(256 + 64 + 8576 + 192 + 128 == PP_APP_SMALL_BYTES, "the record's parts");

static size_t SmallAt(int K)
{
    size_t at = 0;
    int    i;

    for (i = 0; i < K; i++)
    {
        at += k_SmallCap[i];
    }
    return at;
}

static size_t CopyAt(int K)
{
    size_t at = 0;
    int    i;

    for (i = 0; i < K; i++)
    {
        at += k_CopyCap[i];
    }
    return at;
}

static const uint8_t k_Zero64[64];
static const uint8_t k_Garbage[3] = {'P', 'P', 'D'}; /* bytes that are no part: a part present that does not read */

/* a release's part on file is its table's image attestation, then the part */
static uint8_t    s_File[64 + PP_PART_PACKED_MAX];
static pp_durable s_Saved;

/* ----------------------------------------------------------------- the step's records */
static void Collect(PP_AppDist_t *D)
{
    size_t k;

    for (k = 0; k < D->Pep.n_out && D->Step.N < PP_APP_OUTBOX; k++)
    {
        memcpy(D->Step.Record[D->Step.N], D->Pep.out[k], D->Pep.out_len[k]);
        D->Step.Len[D->Step.N++] = D->Pep.out_len[k];
    }
    D->Pep.n_out = 0;
}

static void Begin(PP_AppDist_t *D, long long Now)
{
    memset(&D->Step, 0, sizeof(D->Step));
    D->Now = Now;
}

static void End(PP_AppDist_t *D)
{
    if (D->Pep.held != D->WasHeld)
    {
        D->Step.HoldBegan = D->Pep.held;
        D->Step.HoldEnded = !D->Pep.held;
        D->WasHeld        = D->Pep.held;
    }
}

/* ----------------------------------------------------------------- the stores */
static const uint8_t *ReleaseSig(const PP_AppDist_t *D, int Part)
{
    if (Part == PP_PART_ACTIVE)
    {
        return D->Switching ? D->NextActiveSig : D->ActiveSig;
    }
    if (Part == PP_PART_PREVIOUS)
    {
        return D->Switching ? D->NextPreviousSig : D->PreviousSig;
    }
    return k_Zero64;
}

/* pp_persist_fn: each part the core says changed, whole, to its store; the record and the copy area once each */
static void Persist(void *Ctx, const pp_durable *Durable, int Parts)
{
    PP_AppDist_t *D      = (PP_AppDist_t *)Ctx;
    int           record = 0;
    int           copy   = 0;
    int           k;

    for (k = 0; k < PP_APP_SMALL_PARTS; k++)
    {
        if (Parts & k_SmallPart[k])
        {
            D->Record.Len[k] = (uint32_t)pp_durable_pack(Durable, k_SmallPart[k], D->Record.Bytes + SmallAt(k),
                                                         k_SmallCap[k]);
            record = 1;
        }
    }
    for (k = 0; k < 3; k++)
    {
        if (Parts & k_FilePart[k])
        {
            size_t n = pp_durable_pack(Durable, k_FilePart[k], s_File + 64, sizeof(s_File) - 64);
            memcpy(s_File, ReleaseSig(D, k_FilePart[k]), 64);
            if (n != 0)
            {
                (void)D->Store.WriteFile(D->Store.Ctx, PP_AppDistFiles[k], s_File, 64 + n);
            }
        }
    }
    for (k = 0; k < PP_APP_COPY_PARTS; k++)
    {
        if (Parts & k_CopyPart[k])
        {
            size_t n = pp_durable_pack(Durable, k_CopyPart[k], D->Copy.Bytes + CopyAt(k), k_CopyCap[k]);
            D->Copy.Len[k] = (uint32_t)n;
            if (n != 0)
            {
                (void)D->Store.WriteFile(D->Store.Ctx, PP_AppDistFiles[3 + k], D->Copy.Bytes + CopyAt(k), n);
            }
            copy = 1;
        }
    }
    if (record)
    {
        D->Record.Magic = PP_APP_RECORD_MAGIC;
        D->Record.Size  = (uint32_t)sizeof(D->Record);
        (void)D->Store.SaveRecord(D->Store.Ctx);
    }
    if (copy)
    {
        D->Copy.Magic = PP_APP_COPY_MAGIC;
        D->Copy.Size  = (uint32_t)sizeof(D->Copy);
        (void)D->Store.SaveCopy(D->Store.Ctx);
    }
}

int PP_AppDist_SaveRun(PP_AppDist_t *D)
{
    D->Record.Magic = PP_APP_RECORD_MAGIC;
    D->Record.Size  = (uint32_t)sizeof(D->Record);
    return D->Store.SaveRecord(D->Store.Ctx);
}

/* ----------------------------------------------------------------- the runtime: the kernel */
static const uint8_t *TableOf(const pp_release *Release, uint8_t BodySha[32])
{
    size_t k;

    for (k = 0; k < Release->n; k++)
    {
        if (Release->held[k].envelope.artifact == PP_ART_CFS_TABLE && Release->held[k].body_len == PP_CFS_TABLE_MAX)
        {
            if (BodySha != NULL)
            {
                memcpy(BodySha, Release->held[k].envelope.body_sha256, 32);
            }
            return pp_held_body((pp_release *)Release, k);
        }
    }
    return NULL;
}

/* pp_runtime_fn: the kernel decides with the active release's table, or with nothing. A fallback policy is held by
 * the core, which decides under it; the kernel holds only a release's table. */
static void Runtime(void *Ctx, const pp_release *Active, const pp_statement *Fallback)
{
    PP_AppDist_t  *D = (PP_AppDist_t *)Ctx;
    const uint8_t *body;

    (void)Fallback;
    body = Active != NULL ? TableOf(Active, D->ActiveDigest) : NULL;
    if (body == NULL)
    {
        PP_Kernel_Deactivate();
        return;
    }
    memset(&D->Active, 0, sizeof(D->Active));
    memcpy(&D->Active, body, PP_CFS_TABLE_MAX);
    memcpy(D->Active.ImageSig, ReleaseSig(D, PP_PART_ACTIVE), 64);
    if (PP_Kernel_Activate(&D->Active) != 0)
    {
        PP_Kernel_Deactivate(); /* V11 ran the kernel's check, so this does not happen; if it did, nothing decides */
    }
}

/* V11 on cfs: the kernel's own check of a table, beyond the core's header checks (section 3) */
static uint8_t TableCheck(void *Ctx, const uint8_t *Body, size_t Len)
{
    static PP_PolicyTable_t table;
    int                     rc;

    (void)Ctx;
    if (Len != PP_CFS_TABLE_MAX)
    {
        return 69; /* image:truncated-header */
    }
    memset(&table, 0, sizeof(table));
    memcpy(&table, Body, Len);
    rc = PP_Kernel_Check(&table);
    return (uint8_t)rc;
}

/* ----------------------------------------------------------------- the frames */
/* frames.admit_through_v8: the sealed envelope verified with no body, V9's body mismatch the only refusal that means it
 * passed V2 to V8 (B9) */
static uint8_t Admit(void *Ctx, const uint8_t *Sealed, size_t Len, long long *BodySize, uint8_t BodySha[32],
                     int *TrustBounded)
{
    static pp_pep     view;
    static pp_verdict verdict;
    PP_AppDist_t     *D = (PP_AppDist_t *)Ctx;

    pp_pep_view(&D->Pep, &view);
    pp_verify(Sealed, Len, (const uint8_t *)"", 0, &D->Pep.d.trust, &view, D->Now, &verdict);
    if (D->Pep.locked && !(verdict.has_envelope && verdict.envelope.artifact >= PP_ART_INSTALL_FLOOR &&
                           verdict.envelope.artifact <= PP_ART_INSTALL_TRUST))
    {
        return PP_CAUSE_FLOOR_LOST; /* Q5: a locked PEP admits no release, and still takes install statements */
    }
    if (verdict.cause == 0 || (verdict.cause == PP_CAUSE_BODY_MISMATCH && verdict.envelope.body_size > 0))
    {
        *BodySize = verdict.envelope.body_size;
        memcpy(BodySha, verdict.envelope.body_sha256, 32);
        *TrustBounded = verdict.trust_bounded;
        return 0;
    }
    return verdict.cause;
}

/* ----------------------------------------------------------------- the switch, through the table service */
/* Load the table of `Target` with `Sig` through the table service, whose validation holds it to the switch being
 * made. 0 when the table service took it; the core is then asked to make the switch at the same `now`. */
static int Switch(PP_AppDist_t *D, const pp_release *Target, const uint8_t Sig[64], int Rollback)
{
    uint8_t        body_sha[32], digest[32];
    const uint8_t *body = TableOf(Target, body_sha);
    int            rc;

    if (body == NULL)
    {
        return -1;
    }
    memset(&D->PendingTable, 0, sizeof(D->PendingTable));
    memcpy(&D->PendingTable, body, PP_CFS_TABLE_MAX);
    memcpy(D->PendingTable.ImageSig, Sig, 64);
    rc = PP_Run_CheckTable(&D->Keys, &D->PendingTable, body_sha, digest);
    if (rc != 0)
    {
        /* the run could not attest the image this table decides with: refused, and the release stays staged */
        pp_pep_refuse(&D->Pep, (uint8_t)rc, D->Now);
        Collect(D);
        D->Step.TableCause = (uint8_t)rc;
        return -1;
    }
    D->Pending         = 1;
    D->PendingRollback = Rollback;
    memcpy(D->PendingStream, Target->stream, sizeof(D->PendingStream));
    D->PendingSeq = Target->seq;
    memcpy(D->PendingPolicy, Target->policy_sha256, 32);
    rc         = D->Store.LoadTable(D->Store.Ctx, &D->PendingTable);
    D->Pending = 0;
    if (rc != 0)
    {
        D->Step.TableBusy = 1; /* the table service kept what it held, and so does the core */
        return -1;
    }
    return 0;
}

int PP_AppDist_LoadActive(PP_AppDist_t *D)
{
    int rc;

    if (!D->Started || !PP_Kernel_Active())
    {
        return -1;
    }
    D->PendingTable = D->Active;
    D->Pending      = 2;
    rc              = D->Store.LoadTable(D->Store.Ctx, &D->PendingTable);
    D->Pending      = 0;
    return rc;
}

int PP_AppDist_ValidateTable(PP_AppDist_t *D, const PP_PolicyTable_t *Table)
{
    int rc;

    if (!D->Pending)
    {
        return PP_CAUSE_NOT_STAGED; /* no envelope admits it: only a switch the core is making is loaded */
    }
    if (memcmp(Table, &D->PendingTable, sizeof(*Table)) != 0)
    {
        return PP_CAUSE_BODY_MISMATCH;
    }
    rc = PP_Kernel_Check(Table);
    if (rc != 0 || D->Pending == 2)
    {
        return rc; /* 2: the table that decides now, shown again after a start */
    }
    return D->PendingRollback ? pp_pep_rollback_check(&D->Pep, D->Now)
                              : pp_pep_commit_check(&D->Pep, D->PendingStream, D->PendingSeq, D->PendingPolicy, D->Now);
}

static void CommitNamed(PP_AppDist_t *D, const uint8_t *Frame, size_t Len, const uint8_t Sig[64])
{
    static const uint8_t zero[32];
    const pp_durable    *d = &D->Pep.d;
    char                 stream[PP_STREAM_MAX + 1];
    long long            seq;
    uint8_t              policy[32];
    uint8_t              cause;

    pp_pep_tick(&D->Pep, 0, D->Now); /* the expiry check first, so the answers below are made at one state */
    Collect(D);
    if (!d->has_staged || (Frame != NULL && !pp_frame_names(Frame, Len, d->staged.stream, d->staged.seq,
                                                            d->staged.policy_sha256)))
    {
        pp_pep_commit(&D->Pep, "", 0, zero, 0, 0, D->Now); /* C1: names nothing staged */
        Collect(D);
        return;
    }
    memcpy(stream, d->staged.stream, sizeof(stream));
    seq = d->staged.seq;
    memcpy(policy, d->staged.policy_sha256, 32);
    cause = pp_pep_commit_check(&D->Pep, stream, seq, policy, D->Now);
    if (cause != 0 || Switch(D, &d->staged, Sig, 0) != 0)
    {
        if (cause != 0)
        {
            pp_pep_commit(&D->Pep, stream, seq, policy, 0, 0, D->Now); /* the refusal the check answered */
            Collect(D);
        }
        return;
    }
    D->Switching = 1;
    memcpy(D->NextActiveSig, Sig, 64);
    memcpy(D->NextPreviousSig, D->ActiveSig, 64);
    pp_pep_commit(&D->Pep, stream, seq, policy, 0, 0, D->Now);
    Collect(D);
    if (d->has_active && d->active.seq == seq && memcmp(d->active.policy_sha256, policy, 32) == 0)
    {
        memcpy(D->ActiveSig, D->NextActiveSig, 64);
        memcpy(D->PreviousSig, D->NextPreviousSig, 64);
    }
    D->Switching = 0;
}

/* ----------------------------------------------------------------- provisioning */
static int Provision(PP_AppDist_t *D, const PP_AppDistConfig_t *Cfg, int Bring, long long Now)
{
    static pp_trust          anchor;
    static pp_install_anchor install;
    pp_brought               brought[PP_APP_BROUGHT_MAX];
    char                     stream[PP_STREAM_MAX + 1];
    pp_target                target;
    size_t                   n = 0;
    size_t                   k;

    if (Cfg->Anchor == NULL ||
        pp_read_anchor(Cfg->Anchor, Cfg->AnchorLen, &anchor, &install, stream, &target, D->Step.Fingerprint) != 0 ||
        target != PP_TGT_CFS)
    {
        return -1;
    }
    for (k = 0; Bring && k < Cfg->NBrought && k < PP_APP_BROUGHT_MAX; k++)
    {
        brought[n].sealed     = Cfg->Brought[k].Sealed;
        brought[n].sealed_len = Cfg->Brought[k].SealedLen;
        brought[n].body       = Cfg->Brought[k].Body;
        brought[n].body_len   = Cfg->Brought[k].BodyLen;
        n++;
    }
    if (pp_pep_provision_install(&D->Pep, &anchor, install.present ? &install : NULL, stream, brought, n, Now) != 0)
    {
        return -1;
    }
    D->Step.Provisioned = 1;
    Collect(D);
    return 0;
}

/* ----------------------------------------------------------------- start */
static void ReadPart(PP_AppDist_t *D, int Part, const uint8_t *Bytes, size_t Len, int *Read)
{
    if (!*Read && Bytes != NULL && Len > 0)
    {
        *Read = pp_durable_unpack(&s_Saved, Part, Bytes, Len) == 0;
    }
    (void)D;
}

int PP_AppDist_Start(PP_AppDist_t *D, const PP_AppDistConfig_t *Cfg, int Record, int Copy, uint32_t NowMs,
                     long long Now)
{
    static char doc[1024];
    size_t      doc_len;
    int         k;

    Begin(D, Now);
    (void)NowMs;
    D->Started = 0;
    D->Due     = 0;
    D->Pending = 0;
    /* AF10: the layout the app was built with, and its document's hash, which is also the domain (CL4) */
    memset(&D->Layout, 0, sizeof(D->Layout));
    for (k = 0; k < PRISMPATH_APP_FIELD_COUNT; k++)
    {
        pp_layout_field *f = &D->Layout.fields[D->Layout.n++];
        int32_t          lo, hi;
        uint32_t         stale;
        f->role  = (uint8_t)PP_Kernel_FieldRole(k, Cfg->MonitorStale, &lo, &hi, &stale);
        f->reg   = (uint16_t)k;
        f->min   = lo;
        f->max   = hi;
        f->stale = stale;
    }
    doc_len = PP_Kernel_LayoutDocument(Cfg->MonitorStale, doc, sizeof(doc));
    pp_sha256((const uint8_t *)doc, doc_len, D->Layout.sha256);
    memset(&D->Config, 0, sizeof(D->Config));
    D->Config.kind        = PP_TGT_CFS;
    D->Config.expiry_hold = Cfg->ExpiryResponse == PP_EXPIRY_HOLD;
    D->Config.has_clock   = 1;
    memcpy(D->Config.instance_seed, Cfg->InstanceSeed, 32);
    D->Config.layout     = &D->Layout;
    D->Config.has_domain = 1;
    memcpy(D->Config.domain_sha256, D->Layout.sha256, 32);
    D->Config.persist     = Persist;
    D->Config.runtime     = Runtime;
    D->Config.context     = D;
    D->Config.table_check = TableCheck;

    /* the durable state from its stores: the record's parts, the release files, each install part from its first
     * copy that reads */
    memset(&s_Saved, 0, sizeof(s_Saved));
    memset(D->ActiveSig, 0, 64);
    memset(D->PreviousSig, 0, 64);
    for (k = 0; k < PP_APP_SMALL_PARTS; k++)
    {
        if (Record == PP_APP_STORE_READ && D->Record.Len[k] > 0u && D->Record.Len[k] <= k_SmallCap[k])
        {
            (void)pp_durable_unpack(&s_Saved, k_SmallPart[k], D->Record.Bytes + SmallAt(k), D->Record.Len[k]);
        }
        else if (Record == PP_APP_STORE_LOST)
        {
            (void)pp_durable_unpack(&s_Saved, k_SmallPart[k], k_Garbage, sizeof(k_Garbage));
        }
        else
        {
            (void)pp_durable_unpack(&s_Saved, k_SmallPart[k], NULL, 0);
        }
    }
    for (k = 0; k < 3; k++)
    {
        int32_t n = D->Store.ReadFile(D->Store.Ctx, PP_AppDistFiles[k], s_File, sizeof(s_File));
        if (n < 0)
        {
            (void)pp_durable_unpack(&s_Saved, k_FilePart[k], NULL, 0);
        }
        else if (n <= 64 || pp_durable_unpack(&s_Saved, k_FilePart[k], s_File + 64, (size_t)n - 64u) != 0)
        {
            (void)pp_durable_unpack(&s_Saved, k_FilePart[k], k_Garbage, sizeof(k_Garbage));
        }
        else if (k < 2)
        {
            memcpy(k == 0 ? D->ActiveSig : D->PreviousSig, s_File, 64);
        }
    }
    for (k = 0; k < PP_APP_COPY_PARTS; k++)
    {
        int     read = 0, present = 0;
        int32_t n    = D->Store.ReadFile(D->Store.Ctx, PP_AppDistFiles[3 + k], s_File, sizeof(s_File));
        if (n >= 0)
        {
            present = 1;
            ReadPart(D, k_CopyPart[k], s_File, (size_t)n, &read);
        }
        if (Copy != PP_APP_STORE_ABSENT)
        {
            present = 1;
        }
        if (Copy == PP_APP_STORE_READ && D->Copy.Len[k] > 0u && D->Copy.Len[k] <= k_CopyCap[k])
        {
            ReadPart(D, k_CopyPart[k], D->Copy.Bytes + CopyAt(k), D->Copy.Len[k], &read);
        }
        if (!read)
        {
            (void)pp_durable_unpack(&s_Saved, k_CopyPart[k], present ? k_Garbage : NULL, present ? sizeof(k_Garbage) : 0);
        }
    }
    if (Record != PP_APP_STORE_READ)
    {
        PP_Run_Init(&D->Record.Run); /* a new run, as a store that held none or one that does not read begins */
        memset(D->Record.Len, 0, sizeof(D->Record.Len));
    }

    if (Record == PP_APP_STORE_LOST && Cfg->LostFloor == PP_LOST_FLOOR_MINIMUM)
    {
        /* MINIMUM: provisioned again from the anchor the boot image holds, with the floor one below the minimum */
        (void)pp_pep_open(&D->Pep, &D->Config, &s_Saved, Now);
        D->Pep.n_out = 0;
        if (Provision(D, Cfg, 0, Now) != 0)
        {
            return -1;
        }
        D->Pep.d.floor_seq   = Cfg->MinSeq > 1 ? Cfg->MinSeq - 1 : 0;
        D->Pep.d.n_floor_ids = 0;
        Persist(D, &D->Pep.d, PP_PART_FLOOR);
        D->Step.FloorAt = 1;
    }
    else if (!s_Saved.provisioned)
    {
        if (pp_pep_open(&D->Pep, &D->Config, NULL, Now) != 0 || Provision(D, Cfg, 1, Now) != 0)
        {
            return -1; /* P1: with no anchor the PEP believes nothing */
        }
    }
    else
    {
        if (pp_pep_open(&D->Pep, &D->Config, &s_Saved, Now) != 0)
        {
            return -1; /* X10, K2 */
        }
        Collect(D);
        D->Step.Locked = Record == PP_APP_STORE_LOST;
    }
    pp_assembler_init(&D->Assembler, Admit, D, 0, PP_FRAME_LIMIT, PP_CFS_TABLE_MAX);
    D->Started = 1;
    D->WasHeld = D->Pep.held;
    /* the boot release, as if offered, when no release is active */
    if (!D->Pep.d.has_active && !D->Pep.locked && Cfg->NBoot > 0)
    {
        size_t k2;
        int    table = -1;
        for (k2 = 0; k2 < Cfg->NBoot && k2 < PP_APP_BOOT_MAX; k2++)
        {
            pp_pep_stage(&D->Pep, Cfg->Boot[k2].Sealed, Cfg->Boot[k2].SealedLen, Cfg->Boot[k2].Body,
                         Cfg->Boot[k2].BodyLen, Now);
            Collect(D);
            if (Cfg->Boot[k2].HasImageSig)
            {
                table = (int)k2;
            }
        }
        if (table >= 0)
        {
            CommitNamed(D, NULL, 0, Cfg->Boot[table].ImageSig);
        }
    }
    End(D);
    return 0;
}

/* ----------------------------------------------------------------- the steps */
void PP_AppDist_Frame(PP_AppDist_t *D, const uint8_t *Frame, size_t Len, uint32_t NowMs, long long Now)
{
    uint8_t cause = 0;
    int     event;

    Begin(D, Now);
    if (!D->Started)
    {
        return;
    }
    if (Len >= 1 && (Frame[0] == PP_FRAME_COMMIT || Frame[0] == PP_FRAME_ABORT))
    {
        PP_AppDist_Control(D, Frame, Len, k_Zero64, NowMs, Now); /* a commit with no attestation is refused */
        return;
    }
    event = pp_assembler_receive(&D->Assembler, Frame, Len, NowMs, &cause);
    if (event == PP_ASM_WHOLE)
    {
        pp_pep_stage(&D->Pep, D->Assembler.t.sealed, D->Assembler.t.sealed_len, D->Assembler.t.body,
                     D->Assembler.t.body_len, Now);
        Collect(D);
    }
    else if (event == PP_ASM_DROPPED)
    {
        D->Step.Dropped = cause;
        if (cause != PP_CAUSE_FRAME_INVALID)
        {
            /* G1: an envelope the verifier refused before its body was read (B9) is reported as a refused stage is */
            pp_pep_refuse(&D->Pep, cause, Now);
            Collect(D);
        }
    }
    else if (event == PP_ASM_CONTROL && Frame[0] == PP_FRAME_EPOCH && Len == 12)
    {
        uint64_t epoch = 0;
        int      k;
        for (k = 7; k >= 0; k--)
        {
            epoch = epoch << 8 | Frame[4 + k];
        }
        pp_pep_see_epoch(&D->Pep, epoch);
    }
    End(D);
}

void PP_AppDist_Control(PP_AppDist_t *D, const uint8_t *Frame, size_t Len, const uint8_t ImageSig[64], uint32_t NowMs,
                        long long Now)
{
    static const uint8_t zero[32];
    uint8_t              cause = 0;
    const pp_durable    *d     = &D->Pep.d;

    Begin(D, Now);
    if (!D->Started)
    {
        return;
    }
    if (pp_assembler_receive(&D->Assembler, Frame, Len, NowMs, &cause) != PP_ASM_CONTROL ||
        (Frame[0] != PP_FRAME_COMMIT && Frame[0] != PP_FRAME_ABORT))
    {
        D->Step.Dropped = cause ? cause : PP_CAUSE_FRAME_INVALID;
        End(D);
        return;
    }
    if (Frame[0] == PP_FRAME_ABORT)
    {
        if (d->has_staged && pp_frame_names(Frame, Len, d->staged.stream, d->staged.seq, d->staged.policy_sha256))
        {
            char      stream[PP_STREAM_MAX + 1];
            long long seq = d->staged.seq;
            uint8_t   policy[32];
            memcpy(stream, d->staged.stream, sizeof(stream));
            memcpy(policy, d->staged.policy_sha256, 32);
            pp_pep_abort(&D->Pep, stream, seq, policy, Now);
        }
        else
        {
            pp_pep_abort(&D->Pep, "", 0, zero, Now); /* A1: an abort that names anything else changes nothing */
        }
        Collect(D);
    }
    else if (pp_frame_delay(Frame, Len) != 0)
    {
        D->Due   = 1; /* B8: at the app's own time plus the delay, so a group flips together */
        D->DueMs = NowMs + pp_frame_delay(Frame, Len);
        memcpy(D->DueFrame, Frame, 46);
        memcpy(D->DueSig, ImageSig, 64);
    }
    else
    {
        CommitNamed(D, Frame, Len, ImageSig);
    }
    End(D);
}

void PP_AppDist_Tick(PP_AppDist_t *D, uint32_t NowMs, long long Now)
{
    Begin(D, Now);
    if (!D->Started)
    {
        return;
    }
    pp_pep_tick(&D->Pep, NowMs, Now);
    Collect(D);
    if (D->Due && (int32_t)(NowMs - D->DueMs) >= 0)
    {
        D->Due = 0;
        CommitNamed(D, D->DueFrame, sizeof(D->DueFrame), D->DueSig);
    }
    End(D);
}

void PP_AppDist_Rollback(PP_AppDist_t *D, long long Now)
{
    const pp_durable *d = &D->Pep.d;
    uint8_t           kept[32];
    uint8_t           cause;

    Begin(D, Now);
    if (!D->Started)
    {
        return;
    }
    pp_pep_tick(&D->Pep, 0, Now);
    Collect(D);
    cause = pp_pep_rollback_check(&D->Pep, Now);
    if (cause != 0)
    {
        (void)pp_pep_rollback(&D->Pep, Now); /* its refusal, or nothing when no release is kept */
        Collect(D);
        End(D);
        return;
    }
    memcpy(kept, d->previous.release, 32);
    if (Switch(D, &d->previous, D->PreviousSig, 1) != 0)
    {
        End(D);
        return;
    }
    D->Switching = 2;
    memcpy(D->NextActiveSig, D->PreviousSig, 64);
    memset(D->NextPreviousSig, 0, 64);
    (void)pp_pep_rollback(&D->Pep, Now);
    Collect(D);
    if (d->has_active && memcmp(d->active.release, kept, 32) == 0)
    {
        memcpy(D->ActiveSig, D->NextActiveSig, 64);
        memset(D->PreviousSig, 0, 64);
    }
    D->Switching = 0;
    End(D);
}

void PP_AppDist_Beat(PP_AppDist_t *D, long long Now)
{
    Begin(D, Now);
    if (!D->Started)
    {
        return;
    }
    pp_pep_record(&D->Pep, PP_EV_BEAT, Now);
    Collect(D);
    End(D);
}

/* ----------------------------------------------------------------- one proposal */
static uint8_t KindOf(uint8_t Outcome)
{
    return Outcome == PP_OUT_ALLOW ? PP_KIND_ALLOW : Outcome == PP_OUT_ESCALATE ? PP_KIND_ESCALATE : PP_KIND_REFUSE;
}

void PP_AppDist_Propose(PP_AppDist_t *D, const PP_RunIo_t *Io, const uint8_t *Payload, size_t PayloadLen,
                        uint32_t MonitorAge, long long Now, PP_AppDecision_t *Out)
{
    static uint8_t regs[4 + 8 * PRISMPATH_APP_FIELD_COUNT];
    uint32_t       ages[PRISMPATH_APP_FIELD_COUNT];
    PP_Verdict_t   verdict;
    pp_decision    asked;
    size_t         n;
    int            k;
    int            receipt = 0;

    Begin(D, Now);
    memset(Out, 0, sizeof(*Out));
    Out->Kind  = PP_KIND_REFUSE;
    Out->Cause = PP_NO_IMAGE_CAUSE;
    Out->Rule  = -1;
    Out->Field = -1;
    if (!D->Started)
    {
        return;
    }
    for (k = 0; k < PRISMPATH_APP_FIELD_COUNT; k++)
    {
        ages[k] = D->Layout.fields[k].role == PP_ROLE_INDEPENDENT ? MonitorAge : PP_AGE_NONE;
    }
    n = PP_Kernel_Registers(Payload, PayloadLen, regs, sizeof(regs), &verdict);
    if (n == 0)
    {
        /* the boundary: a reading outside its field definitions is refused before any set decides (section 9.4) */
        int mark = 0;
        (void)pp_pep_decide(&D->Pep, &mark, Now);
        Collect(D);
        Out->Basis = PP_Kernel_Active() ? PP_BASIS_RELEASE : PP_BASIS_NONE;
        Out->Held  = mark;
        receipt    = PP_Kernel_Active();
    }
    else
    {
        pp_pep_ask(&D->Pep, regs, n, ages, Now, &asked);
        Collect(D);
        Out->Basis = asked.basis;
        Out->Held  = asked.held_mark;
        if (asked.basis == PP_BASIS_RELEASE)
        {
            PP_Kernel_Decide(Payload, PayloadLen, &verdict);
            if (verdict.Kind != KindOf(asked.outcome) || (verdict.Kind != PP_KIND_ALLOW && verdict.Cause != asked.cause))
            {
                Out->RecordError = 1; /* the kernel and the core read the table apart: nothing is carried out */
                End(D);
                return;
            }
            receipt = 1;
        }
        else
        {
            verdict.Kind   = PP_KIND_REFUSE;
            verdict.Cause  = asked.basis == PP_BASIS_NONE ? asked.cause : PP_NO_IMAGE_CAUSE;
            verdict.Rule   = -1;
            verdict.Field  = -1;
            verdict.Reason = PP_REASON_NONE;
            Out->NotEnacted = asked.basis == PP_BASIS_FLOOR || asked.basis == PP_BASIS_FALLBACK;
        }
    }
    Out->Kind  = verdict.Kind;
    Out->Cause = verdict.Cause;
    Out->Rule  = verdict.Rule;
    Out->Field = verdict.Field;
    if (receipt)
    {
        if (PP_Run_Record(&D->Record.Run, Io, &D->Keys, &D->Active, D->ActiveDigest, Payload, PayloadLen, &verdict,
                          Out->Held, &Out->Receipt) == 0)
        {
            Out->Receipted = 1;
            (void)PP_AppDist_SaveRun(D);
        }
        else
        {
            Out->RecordError = 1;
        }
    }
    End(D);
}

/* ----------------------------------------------------------------- the ground's statement files */
static uint32_t U32(const uint8_t *P)
{
    return (uint32_t)P[0] | (uint32_t)P[1] << 8 | (uint32_t)P[2] << 16 | (uint32_t)P[3] << 24;
}

int PP_AppDist_ReadStatement(const uint8_t *Data, size_t Len, PP_AppStatement_t *Out)
{
    size_t at = 4;
    size_t n;

    memset(Out, 0, sizeof(*Out));
    if (Len < 13 || memcmp(Data, "PPST", 4) != 0)
    {
        return -1;
    }
    n = U32(Data + at);
    at += 4;
    if (n < 1 || n > PP_MAX_SEALED || at + n + 5 > Len)
    {
        return -1;
    }
    Out->Sealed    = Data + at;
    Out->SealedLen = n;
    at += n;
    n = U32(Data + at);
    at += 4;
    if (n > PP_INSTALL_BODY_MAX || at + n + 1 > Len)
    {
        return -1;
    }
    Out->Body    = Data + at;
    Out->BodyLen = n;
    at += n;
    Out->HasImageSig = Data[at++];
    if (Out->HasImageSig > 1 || at + (Out->HasImageSig ? 64u : 0u) != Len)
    {
        return -1;
    }
    if (Out->HasImageSig)
    {
        memcpy(Out->ImageSig, Data + at, 64);
    }
    return 0;
}
