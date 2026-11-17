/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The app's receipts as a signed core run. See prismpath_app_run.h.
 *
 * Every document here is written in its canon/2 spelling by hand: no whitespace, members in key order, the
 * strings plain ASCII that needs no escape (hex digests, the fixed format names, field names, the case id
 * v<version>), integers in decimal. The flow string is the one exception, and the table carries it already
 * spelled. tests/test_cfs_run.py holds every byte to the Python writers.
 *
 * Storage is static. Nothing is allocated.
 */
#include <string.h>

#include "prismpath_app_run.h"
#include "prismpath_app_layout.h"
#include "monocypher-ed25519.h"

/* OSAL limits a file name to 19 characters (OS_MAX_FILE_NAME 20 with its NUL), and the core run's root statement
 * file, receipts.roots.jsonl, is 20: onboard it is roots.jsonl, and the ground's copy takes its own name back
 * (integrations/cfs/ground/downlink.py, fetch). Every other file has the core run's name. */
const char *const PP_RunFileNames[PP_FILE_COUNT] = {
    "receipts.jsonl", "cases.stream",    "images.jsonl",  "cases.jsonl",  "run.json",
    "roots.jsonl",    "roots.log.jsonl", "authority.pub", "instance.pub",
};

/* the domain prefixes the signatures are taken over, NUL included (core_evidence.IMAGE_DOMAIN, ROOT_DOMAIN) */
static const char k_ImageDomain[] = "prismpath.core-image/1";   /* + its NUL: 23 bytes */
static const char k_RootDomain[]  = "prismpath.core-run-root/2"; /* + its NUL: 26 bytes */
static const char k_TableDomain[] = "prismpath.cfs-table/1";    /* + its NUL: 22 bytes */

/* the registered causes this module answers with (prismpath/kernel/causes.py) */
enum
{
    R_SIG_MISSING    = 1,
    R_SIG_INVALID    = 2,
    R_VERSION_REPLAY = 9,
    R_SHORT          = 69
};

/* ----------------------------------------------------------------- writing canon/2 by hand */
typedef struct
{
    char  *P;
    size_t Len;
    size_t Cap;
    int    Err;
} Buf_t;

static void Put(Buf_t *B, const void *Data, size_t Len)
{
    if (B->Err || Len > B->Cap - B->Len)
    {
        B->Err = 1;
        return;
    }
    memcpy(B->P + B->Len, Data, Len);
    B->Len += Len;
}

static void PutS(Buf_t *B, const char *S)
{
    Put(B, S, strlen(S));
}

static void PutU64(Buf_t *B, uint64_t V)
{
    char digits[21];
    int  n = 0;
    char out[21];
    int  i;

    do
    {
        digits[n++] = (char)('0' + (V % 10u));
        V /= 10u;
    } while (V != 0u);
    for (i = 0; i < n; i++)
    {
        out[i] = digits[n - 1 - i];
    }
    Put(B, out, (size_t)n);
}

static void PutHex(Buf_t *B, const uint8_t *Data, size_t Len)
{
    static const char k_Hex[] = "0123456789abcdef";
    size_t            i;

    for (i = 0; i < Len; i++)
    {
        char pair[2];
        pair[0] = k_Hex[Data[i] >> 4];
        pair[1] = k_Hex[Data[i] & 15u];
        Put(B, pair, 2);
    }
}

/* "key":"hex" */
static void PutHexMember(Buf_t *B, const char *Key, const uint8_t *Data, size_t Len)
{
    PutS(B, "\"");
    PutS(B, Key);
    PutS(B, "\":\"");
    PutHex(B, Data, Len);
    PutS(B, "\"");
}

static void PutCaseId(Buf_t *B, uint32_t Version)
{
    PutS(B, "\"v");
    PutU64(B, Version);
    PutS(B, "\"");
}

static void Sha256(const void *Data, size_t Len, uint8_t Out[32])
{
    ppt_sha256_ctx ctx;

    ppt_sha256_init(&ctx);
    ppt_sha256_update(&ctx, Data, Len);
    ppt_sha256_final(&ctx, Out);
}

/* ----------------------------------------------------------------- the state */
void PP_Run_Init(PP_RunState_t *State)
{
    memset(State, 0, sizeof(*State));
    State->Magic = PP_RUN_MAGIC;
    State->Size  = (uint32_t)sizeof(*State);
    ppt_merkle_acc_init(&State->Acc);
}

int PP_Run_StateValid(const PP_RunState_t *State)
{
    return State->Magic == PP_RUN_MAGIC && State->Size == (uint32_t)sizeof(*State) && State->CaseOpen <= 1u &&
           (State->CaseOpen == 0u || State->CaseCount > 0u) && (uint64_t)State->CaseReadings <= State->Acc.count &&
           (State->Acc.count == 0u || State->CaseCount > 0u);
}

void PP_Run_SetInstanceSeed(PP_RunKeys_t *Keys, uint8_t Seed[32])
{
    crypto_ed25519_key_pair(Keys->InstanceSecret, Keys->InstancePub, Seed);
    Keys->HaveInstance = 1;
}

uint64_t PP_Run_Root(const PP_RunState_t *State, uint8_t Root[32])
{
    (void)ppt_merkle_acc_root(&State->Acc, Root);
    return State->Acc.count;
}

/* ----------------------------------------------------------------- the table */
static uint8_t s_SigMsg[sizeof(k_ImageDomain) + PRISMPATH_APP_CORE_MAX];

int PP_Run_CheckTable(const PP_RunState_t *State, const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Table,
                      uint8_t Digest[32])
{
    uint8_t msg[sizeof(k_TableDomain) + 32];

    if (Table->CoreLen == 0u || Table->CoreLen > PRISMPATH_APP_CORE_MAX || Table->FlowJsonLen < 2u ||
        Table->FlowJsonLen > PRISMPATH_APP_FLOW_MAX || Table->Version == 0u || Table->ContractCause != 37u ||
        Table->NoMatchCause != 32u)
    {
        return R_SHORT;
    }
    Sha256(Table, offsetof(PP_PolicyTable_t, ImageSig), Digest);
    if (!Keys->HaveAuthority)
    {
        return R_SIG_MISSING;
    }
    memcpy(msg, k_TableDomain, sizeof(k_TableDomain));
    memcpy(msg + sizeof(k_TableDomain), Digest, 32);
    if (crypto_ed25519_check(Table->TableSig, Keys->AuthorityPub, msg, sizeof(msg)) != 0)
    {
        return R_SIG_INVALID;
    }
    memcpy(s_SigMsg, k_ImageDomain, sizeof(k_ImageDomain));
    memcpy(s_SigMsg + sizeof(k_ImageDomain), Table->Core, Table->CoreLen);
    if (crypto_ed25519_check(Table->ImageSig, Keys->AuthorityPub, s_SigMsg, sizeof(k_ImageDomain) + Table->CoreLen) !=
        0)
    {
        return R_SIG_INVALID;
    }
    if (State->FloorVersion != 0u &&
        (Table->Version < State->FloorVersion ||
         (Table->Version == State->FloorVersion && memcmp(Digest, State->FloorDigest, 32) != 0)))
    {
        return R_VERSION_REPLAY;
    }
    return 0;
}

void PP_Run_Accept(PP_RunState_t *State, uint32_t Version, const uint8_t Digest[32])
{
    State->FloorVersion = Version;
    memcpy(State->FloorDigest, Digest, 32);
}

/* ----------------------------------------------------------------- the reading and the receipt */
size_t PP_Run_ReadingBytes(const uint8_t *Payload, size_t PayloadLen, char *Out, size_t Cap)
{
    Buf_t B = {Out, 0, Cap, 0};
    int   i;
    int   first = 1;

    PutS(&B, "{");
    for (i = 0; i < PRISMPATH_APP_FIELD_COUNT; i++)
    {
        int32_t value;
        int     is_bool;

        if (!PP_Kernel_FieldValue(Payload, PayloadLen, i, &value, &is_bool))
        {
            continue; /* the payload ends before it: the field is absent from the reading */
        }
        if (!first)
        {
            PutS(&B, ",");
        }
        first = 0;
        PutS(&B, "\"");
        PutS(&B, PP_Kernel_FieldName((int16_t)i));
        PutS(&B, "\":");
        if (is_bool && (value == 0 || value == 1))
        {
            PutS(&B, value ? "true" : "false");
        }
        else
        {
            PutU64(&B, (uint64_t)(uint32_t)value); /* the layout reads unsigned values only */
        }
    }
    PutS(&B, "}");
    return B.Err ? 0 : B.Len;
}

static const char *CauseName(uint16_t Code)
{
    switch (Code)
    {
        case 32:
            return "route:no-matching-edge";
        case 37:
            return "route:contract-violation";
        default:
            return NULL;
    }
}

static const char *ReasonName(uint8_t Reason)
{
    switch (Reason)
    {
        case PP_REASON_MISSING:
            return "missing";
        case PP_REASON_WRONG_TYPE:
            return "wrong_type";
        case PP_REASON_OUT_OF_RANGE:
            return "out_of_range";
        default:
            return NULL;
    }
}

size_t PP_Run_ReceiptBytes(uint64_t Index, uint32_t CaseVersion, uint32_t Reading, const uint8_t ImageSha[32],
                           const uint8_t ReadingSha[32], const PP_Verdict_t *Verdict, const PP_PolicyTable_t *Active,
                           char *Out, size_t Cap)
{
    Buf_t       B     = {Out, 0, Cap, 0};
    const char *cause = NULL;
    const char *reason = NULL;
    int         route = (Verdict->Rule >= 0);

    if (route && (uint16_t)Verdict->Rule >= Active->RuleCount)
    {
        return 0;
    }
    if (!route)
    {
        cause = CauseName(Verdict->Cause);
        if (cause == NULL)
        {
            return 0;
        }
        reason = ReasonName(Verdict->Reason);
        if ((reason == NULL) != (Verdict->Field < 0))
        {
            return 0;
        }
    }
    /* the members in key order: case, cause, cause_code, decider, decision, field, format, idx, image_sha256,
     * reading, reading_sha256, reason, target */
    PutS(&B, "{\"case\":");
    PutCaseId(&B, CaseVersion);
    if (!route)
    {
        PutS(&B, ",\"cause\":\"");
        PutS(&B, cause);
        PutS(&B, "\",\"cause_code\":");
        PutU64(&B, Verdict->Cause);
    }
    PutS(&B, ",\"decider\":\"" PP_RUN_DECIDER "\",\"decision\":");
    PutS(&B, route ? "\"route\"" : "\"refuse\"");
    if (!route && Verdict->Field >= 0)
    {
        PutS(&B, ",\"field\":\"");
        PutS(&B, PP_Kernel_FieldName(Verdict->Field));
        PutS(&B, "\"");
    }
    PutS(&B, ",\"format\":\"prismpath.core-receipt/1\",\"idx\":");
    PutU64(&B, Index);
    PutS(&B, ",");
    PutHexMember(&B, "image_sha256", ImageSha, 32);
    PutS(&B, ",\"reading\":");
    PutU64(&B, Reading);
    PutS(&B, ",");
    PutHexMember(&B, "reading_sha256", ReadingSha, 32);
    if (!route && reason != NULL)
    {
        PutS(&B, ",\"reason\":\"");
        PutS(&B, reason);
        PutS(&B, "\"");
    }
    if (route)
    {
        const PP_Rule_t *rule = &Active->Rules[Verdict->Rule];
        /* the rule's target, as the core image names it: allow, refuse_<code> or escalate_<code> */
        PutS(&B, ",\"target\":\"");
        if (rule->Kind == PP_KIND_ALLOW)
        {
            PutS(&B, "allow");
        }
        else
        {
            PutS(&B, rule->Kind == PP_KIND_REFUSE ? "refuse_" : "escalate_");
            PutU64(&B, rule->Cause);
        }
        PutS(&B, "\"");
    }
    PutS(&B, "}");
    return B.Err ? 0 : B.Len;
}

/* ----------------------------------------------------------------- files */
static int Append(const PP_RunIo_t *Io, int File, const void *Data, size_t Len)
{
    int32_t h = Io->Open(Io->Ctx, File, PP_IO_APPEND);
    int32_t rc;

    if (h < 0)
    {
        return -1;
    }
    rc = Io->Write(Io->Ctx, h, Data, Len);
    Io->Close(Io->Ctx, h);
    return rc == 0 ? 0 : -1;
}

static int Replace(const PP_RunIo_t *Io, int File, const void *Data, size_t Len)
{
    int32_t h = Io->Open(Io->Ctx, File, PP_IO_CREATE);
    int32_t rc;

    if (h < 0)
    {
        return -1;
    }
    rc = (Len == 0u) ? 0 : Io->Write(Io->Ctx, h, Data, Len);
    Io->Close(Io->Ctx, h);
    return rc == 0 ? 0 : -1;
}

int PP_Run_Recover(const PP_RunState_t *State, const PP_RunIo_t *Io)
{
    static const int k_Files[3] = {PP_FILE_RECEIPTS, PP_FILE_STREAM, PP_FILE_IMAGES};
    uint64_t         want[3];
    int              i;
    int              rc = 0;

    want[0] = State->ReceiptsLen;
    want[1] = State->StreamLen;
    want[2] = State->ImagesLen;
    for (i = 0; i < 3; i++)
    {
        int64_t size = Io->Size(Io->Ctx, k_Files[i]);
        if (size < 0)
        {
            size = 0;
        }
        if ((uint64_t)size < want[i])
        {
            rc = -1;
        }
        else if ((uint64_t)size > want[i] && Io->Truncate(Io->Ctx, k_Files[i], want[i]) != 0)
        {
            rc = -1;
        }
    }
    return rc;
}

int PP_Run_Begin(const PP_RunIo_t *Io)
{
    int f;

    for (f = 0; f < PP_FILE_COUNT; f++)
    {
        if (Replace(Io, f, "", 0) != 0)
        {
            return -1;
        }
    }
    return 0;
}

/* ----------------------------------------------------------------- one decision */
static char s_Line[1024];
static char s_Reading[256];

/* the case line's opening, up to the readings array: {"case":..,"flow":..,"image":"<hex>","readings":[ */
static int OpenCase(const PP_RunIo_t *Io, const PP_PolicyTable_t *Active, uint64_t *Written)
{
    Buf_t    B = {s_Line, 0, sizeof(s_Line), 0};
    uint16_t at;
    int32_t  h;
    int      rc = 0;

    h = Io->Open(Io->Ctx, PP_FILE_STREAM, PP_IO_APPEND);
    if (h < 0)
    {
        return -1;
    }
    PutS(&B, "{\"case\":");
    PutCaseId(&B, Active->Version);
    PutS(&B, ",\"flow\":");
    rc |= (B.Err ? -1 : Io->Write(Io->Ctx, h, B.P, B.Len));
    *Written += B.Len;
    rc |= Io->Write(Io->Ctx, h, Active->FlowJson, Active->FlowJsonLen);
    *Written += Active->FlowJsonLen;
    B.Len = 0;
    PutS(&B, ",\"image\":\"");
    rc |= (B.Err ? -1 : Io->Write(Io->Ctx, h, B.P, B.Len));
    *Written += B.Len;
    for (at = 0; at < Active->CoreLen && rc == 0; at = (uint16_t)(at + 256u))
    {
        unsigned left = (unsigned)Active->CoreLen - at;
        uint16_t n    = (uint16_t)(left < 256u ? left : 256u);
        B.Len      = 0;
        PutHex(&B, Active->Core + at, n);
        rc |= (B.Err ? -1 : Io->Write(Io->Ctx, h, B.P, B.Len));
        *Written += B.Len;
    }
    B.Len = 0;
    PutS(&B, "\",\"readings\":[");
    rc |= (B.Err ? -1 : Io->Write(Io->Ctx, h, B.P, B.Len));
    *Written += B.Len;
    Io->Close(Io->Ctx, h);
    return rc == 0 ? 0 : -1;
}

/* the case's image attestation: {"case":..,"format":"prismpath.core-image/1","image_sha256":..,"key_id":..,"sig":..} */
static size_t ImageLine(const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Active, const uint8_t CoreSha[32])
{
    Buf_t   B = {s_Line, 0, sizeof(s_Line), 0};
    uint8_t key_id[32];

    Sha256(Keys->AuthorityPub, 32, key_id);
    PutS(&B, "{\"case\":");
    PutCaseId(&B, Active->Version);
    PutS(&B, ",\"format\":\"prismpath.core-image/1\",");
    PutHexMember(&B, "image_sha256", CoreSha, 32);
    PutS(&B, ",");
    PutHexMember(&B, "key_id", key_id, 32);
    PutS(&B, ",");
    PutHexMember(&B, "sig", Active->ImageSig, 64);
    PutS(&B, "}\n");
    return B.Err ? 0 : B.Len;
}

int PP_Run_Record(PP_RunState_t *State, const PP_RunIo_t *Io, const PP_RunKeys_t *Keys, const PP_PolicyTable_t *Active,
                  const uint8_t ActiveDigest[32], const uint8_t *Payload, size_t PayloadLen, const PP_Verdict_t *Verdict,
                  uint64_t *Index)
{
    PP_RunState_t next = *State;
    uint8_t       core_sha[32];
    uint8_t       reading_sha[32];
    uint8_t       leaf[32];
    size_t        reading_len;
    size_t        len;
    Buf_t         B;

    if (!Keys->HaveAuthority || next.Acc.count == UINT64_MAX)
    {
        return -1;
    }
    Sha256(Active->Core, Active->CoreLen, core_sha);

    /* a new case when the image deciding is not the open case's */
    if (!next.CaseOpen || next.CaseVersion != Active->Version || memcmp(next.CaseDigest, ActiveDigest, 32) != 0)
    {
        if (next.CaseOpen)
        {
            if (Append(Io, PP_FILE_STREAM, "]}\n", 3) != 0)
            {
                goto fail;
            }
            next.StreamLen += 3;
        }
        if (OpenCase(Io, Active, &next.StreamLen) != 0)
        {
            goto fail;
        }
        len = ImageLine(Keys, Active, core_sha);
        if (len == 0 || Append(Io, PP_FILE_IMAGES, s_Line, len) != 0)
        {
            goto fail;
        }
        next.ImagesLen += len;
        next.CaseOpen     = 1;
        next.CaseVersion  = Active->Version;
        memcpy(next.CaseDigest, ActiveDigest, 32);
        next.CaseReadings = 0;
        next.CaseCount++;
    }

    /* the reading, in the case's readings array */
    reading_len = PP_Run_ReadingBytes(Payload, PayloadLen, s_Reading, sizeof(s_Reading));
    if (reading_len == 0)
    {
        goto fail;
    }
    Sha256(s_Reading, reading_len, reading_sha);
    B = (Buf_t){s_Line, 0, sizeof(s_Line), 0};
    if (next.CaseReadings > 0u)
    {
        PutS(&B, ",");
    }
    PutS(&B, "\"");
    PutHex(&B, (const uint8_t *)s_Reading, reading_len);
    PutS(&B, "\"");
    if (B.Err || Append(Io, PP_FILE_STREAM, B.P, B.Len) != 0)
    {
        goto fail;
    }
    next.StreamLen += B.Len;

    /* the receipt, and its leaf */
    len = PP_Run_ReceiptBytes(next.Acc.count, next.CaseVersion, next.CaseReadings, core_sha, reading_sha, Verdict,
                              Active, s_Line, sizeof(s_Line) - 1u);
    if (len == 0)
    {
        goto fail;
    }
    Sha256(s_Line, len, leaf);
    s_Line[len] = '\n';
    if (Append(Io, PP_FILE_RECEIPTS, s_Line, len + 1u) != 0)
    {
        goto fail;
    }
    next.ReceiptsLen += len + 1u;
    *Index = next.Acc.count;
    (void)ppt_merkle_acc_add(&next.Acc, leaf, 32);
    next.CaseReadings++;
    *State = next;
    return 0;

fail:
    (void)PP_Run_Recover(State, Io); /* cut back whatever part of this decision reached the files */
    return -1;
}

/* ----------------------------------------------------------------- sealing */
static uint8_t s_Copy[512];

/* copy (or only hash, when To < 0) a file, returning its SHA-256 context updated with every byte */
static int CopyHash(const PP_RunIo_t *Io, int From, int32_t To, ppt_sha256_ctx *Ctx)
{
    int32_t h = Io->Open(Io->Ctx, From, PP_IO_READ);
    int32_t n;
    int     rc = 0;

    if (h < 0)
    {
        return -1;
    }
    while ((n = Io->Read(Io->Ctx, h, s_Copy, sizeof(s_Copy))) > 0)
    {
        ppt_sha256_update(Ctx, s_Copy, (size_t)n);
        if (To >= 0 && Io->Write(Io->Ctx, To, s_Copy, (size_t)n) != 0)
        {
            rc = -1;
            break;
        }
    }
    if (n < 0)
    {
        rc = -1;
    }
    Io->Close(Io->Ctx, h);
    return rc;
}

static char s_Statement[1024];

int PP_Run_Seal(PP_RunState_t *State, const PP_RunIo_t *Io, const PP_RunKeys_t *Keys, uint64_t TimeUs)
{
    ppt_sha256_ctx ctx;
    uint8_t        cases_sha[32], images_sha[32], run_sha[32], authority_id[32], instance_id[32], root[32], sig[64];
    int32_t        h;
    int            rc;
    Buf_t          B;
    size_t         body;
    uint64_t       leaves;

    if (!Keys->HaveInstance || !Keys->HaveAuthority)
    {
        return -2;
    }
    /* cases.jsonl: the stream, its open case closed */
    h = Io->Open(Io->Ctx, PP_FILE_CASES, PP_IO_CREATE);
    if (h < 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_CASES);
    }
    ppt_sha256_init(&ctx);
    rc = CopyHash(Io, PP_FILE_STREAM, h, &ctx);
    if (rc == 0 && State->CaseOpen)
    {
        ppt_sha256_update(&ctx, "]}\n", 3);
        rc = Io->Write(Io->Ctx, h, "]}\n", 3);
    }
    Io->Close(Io->Ctx, h);
    if (rc != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_STREAM);
    }
    ppt_sha256_final(&ctx, cases_sha);
    ppt_sha256_init(&ctx);
    if (CopyHash(Io, PP_FILE_IMAGES, -1, &ctx) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_IMAGES);
    }
    ppt_sha256_final(&ctx, images_sha);
    Sha256(Keys->AuthorityPub, 32, authority_id);
    Sha256(Keys->InstancePub, 32, instance_id);
    leaves = PP_Run_Root(State, root);

    /* run.json, the manifest */
    B = (Buf_t){s_Line, 0, sizeof(s_Line), 0};
    PutS(&B, "{");
    PutHexMember(&B, "authority_key_id", authority_id, 32);
    PutS(&B, ",\"cases\":");
    PutU64(&B, State->CaseCount);
    PutS(&B, ",");
    PutHexMember(&B, "cases_sha256", cases_sha, 32);
    PutS(&B, ",\"decider\":\"" PP_RUN_DECIDER "\",\"excluded\":[],\"format\":\"prismpath.core-run/1\",");
    PutHexMember(&B, "images_sha256", images_sha, 32);
    PutS(&B, ",");
    PutHexMember(&B, "instance_key_id", instance_id, 32);
    PutS(&B, ",\"receipts\":");
    PutU64(&B, leaves);
    PutS(&B, "}");
    if (B.Err)
    {
        return -1;
    }
    Sha256(B.P, B.Len, run_sha);
    PutS(&B, "\n");
    if (B.Err || Replace(Io, PP_FILE_RUN, B.P, B.Len) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_RUN);
    }

    /* the root statement: the domain, then every member but sig, which is signed; then the line with sig */
    B = (Buf_t){s_Statement, 0, sizeof(s_Statement), 0};
    Put(&B, k_RootDomain, sizeof(k_RootDomain));
    body = B.Len;
    PutS(&B, "{\"format\":\"prismpath.core-run-root/2\",");
    PutHexMember(&B, "key_id", instance_id, 32);
    PutS(&B, ",\"leaves\":");
    PutU64(&B, leaves);
    PutS(&B, ",\"log\":\"core-run\",\"policy\":{");
    PutHexMember(&B, "core_run_sha256", run_sha, 32);
    PutS(&B, "},");
    PutHexMember(&B, "public_key", Keys->InstancePub, 32);
    PutS(&B, ",\"root\":\"");
    if (leaves > 0u)
    {
        PutHex(&B, root, 32); /* no receipts: the empty string, as root_statement.merkle_root spells it */
    }
    PutS(&B, "\"");
    {
        /* the signed form has no sig member: time_us and trigger follow root directly */
        size_t before_tail = B.Len;
        PutS(&B, ",\"time_us\":");
        PutU64(&B, TimeUs);
        PutS(&B, ",\"trigger\":\"core-run\"}");
        if (B.Err)
        {
            return -1;
        }
        crypto_ed25519_sign(sig, Keys->InstanceSecret, (const uint8_t *)B.P, B.Len);
        /* the line: the same members with sig in its place, between root and time_us */
        {
            static char tail[96];
            size_t      tail_len = B.Len - before_tail;
            memcpy(tail, B.P + before_tail, tail_len);
            B.Len = before_tail;
            PutS(&B, ",");
            PutHexMember(&B, "sig", sig, 64);
            Put(&B, tail, tail_len);
            PutS(&B, "\n");
        }
    }
    if (B.Err)
    {
        return -1;
    }
    if (Replace(Io, PP_FILE_ROOTS, B.P + body, B.Len - body) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_ROOTS);
    }
    if (Append(Io, PP_FILE_ROOTLOG, B.P + body, B.Len - body) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_ROOTLOG);
    }
    if (Replace(Io, PP_FILE_AUTHORITY, Keys->AuthorityPub, 32) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_AUTHORITY);
    }
    if (Replace(Io, PP_FILE_INSTANCE, Keys->InstancePub, 32) != 0)
    {
        return PP_SEAL_FILE_ERR(PP_FILE_INSTANCE);
    }
    State->Seals++;
    return 0;
}
