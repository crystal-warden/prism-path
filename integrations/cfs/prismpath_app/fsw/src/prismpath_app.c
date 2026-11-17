/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/** @file
 *   The PrismPath command validation app for cFS.
 *
 * A proposer (the autonomy app) publishes commands on the PROPOSED_CMD message id. This app is the only
 * subscriber. Each proposal is read into the policy's fields as prismpath_app_layout.h defines them, decided
 * by PrismPath's C kernel against the active policy image, and then
 *
 *   allow     receipted, then republished on the VEHICLE_CMD message id, and an event sent
 *   refuse    receipted, an event with the registered cause code, nothing republished
 *   escalate  receipted, an event with the registered cause code, nothing republished (nothing is held yet)
 *
 * Every decision under an active image is a core receipt and a leaf of the run's Merkle tree
 * (prismpath_app_run.h), written before an allowed command is republished: a decision that cannot be receipted
 * is never acted on. The receipts' accumulator and the image version floor live in the Critical Data Store, so a
 * processor reset continues the run and cannot reopen an older image. A SEAL ground command signs a root
 * statement onboard and writes the run, in the layout `prismpath evidence verify` reads, under RUN_DIR.
 *
 * The policy image comes from the cFE table "PolicyTable". Its validation callback runs the kernel's checks, the
 * authority's two signatures and the version floor, and the app runs the same checks again when it activates the
 * image, so an image that fails never decides. All storage is static; nothing is allocated after initialization.
 */
#include <stdio.h>
#include <string.h>

#include "prismpath_app.h"
#include "prismpath_app_eventids.h"
#include "prismpath_app_kernel.h"

/* the command struct and the layout header must agree, byte for byte */
#define PAYLOAD_OFFSET(member) (offsetof(PRISMPATH_APP_ProposedCmd_t, member) - sizeof(CFE_MSG_CommandHeader_t))
_Static_assert(PAYLOAD_OFFSET(CmdClass) == 0, "cmd_class offset");
_Static_assert(PAYLOAD_OFFSET(GroundContact) == 1, "ground_contact offset");
_Static_assert(PAYLOAD_OFFSET(SlewDeg) == 2, "slew_deg offset");
_Static_assert(PAYLOAD_OFFSET(ThrustPct) == 4, "thrust_pct offset");
_Static_assert(sizeof(PRISMPATH_APP_ProposedCmd_t) - sizeof(CFE_MSG_CommandHeader_t) == PRISMPATH_APP_PAYLOAD_LEN,
               "payload length");

PRISMPATH_APP_Data_t PRISMPATH_APP_Data;

/* ----------------------------------------------------------------- the run's files, through OSAL */
#define PP_IO_SLOTS 4
static osal_id_t PP_IoFd[PP_IO_SLOTS];
static bool      PP_IoUsed[PP_IO_SLOTS];

static void PP_IoPath(int File, char *Path, size_t Cap)
{
    snprintf(Path, Cap, "%s/%s", PRISMPATH_APP_PLATFORM_RUN_DIR, PP_RunFileNames[File]);
}

static int32 PP_IoOpen(void *Ctx, int File, int Mode)
{
    char    path[OS_MAX_PATH_LEN];
    int32   slot;
    int32   rc;
    int32   flags  = OS_FILE_FLAG_NONE;
    int32   access = OS_READ_ONLY;

    (void)Ctx;
    for (slot = 0; slot < PP_IO_SLOTS && PP_IoUsed[slot]; slot++)
    {
    }
    if (slot == PP_IO_SLOTS || File < 0 || File >= PP_FILE_COUNT)
    {
        return -1;
    }
    PP_IoPath(File, path, sizeof(path));
    if (Mode == PP_IO_APPEND)
    {
        flags  = OS_FILE_FLAG_CREATE;
        access = OS_WRITE_ONLY;
    }
    else if (Mode == PP_IO_CREATE)
    {
        flags  = OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE;
        access = OS_WRITE_ONLY;
    }
    rc = OS_OpenCreate(&PP_IoFd[slot], path, flags, access);
    if (rc != OS_SUCCESS)
    {
        return -1;
    }
    if (Mode == PP_IO_APPEND && OS_lseek(PP_IoFd[slot], 0, OS_SEEK_END) < 0)
    {
        OS_close(PP_IoFd[slot]);
        return -1;
    }
    PP_IoUsed[slot] = true;
    return slot;
}

static int32 PP_IoWrite(void *Ctx, int32 Handle, const void *Buf, size_t Len)
{
    const uint8 *at = (const uint8 *)Buf;

    (void)Ctx;
    while (Len > 0)
    {
        int32 n = OS_write(PP_IoFd[Handle], at, Len);
        if (n <= 0)
        {
            return -1;
        }
        at += n;
        Len -= (size_t)n;
    }
    return 0;
}

static int32 PP_IoRead(void *Ctx, int32 Handle, void *Buf, size_t Len)
{
    int32 n;

    (void)Ctx;
    n = OS_read(PP_IoFd[Handle], Buf, Len);
    return (n < 0) ? -1 : n;
}

static void PP_IoClose(void *Ctx, int32 Handle)
{
    (void)Ctx;
    OS_close(PP_IoFd[Handle]);
    PP_IoUsed[Handle] = false;
}

static int64 PP_IoSize(void *Ctx, int File)
{
    char       path[OS_MAX_PATH_LEN];
    os_fstat_t st;

    (void)Ctx;
    PP_IoPath(File, path, sizeof(path));
    if (OS_stat(path, &st) != OS_SUCCESS)
    {
        return -1;
    }
    return (int64)OS_FILESTAT_SIZE(st);
}

/* OSAL has no truncate: copy the first Len bytes beside the file and rename the copy over it */
static int32 PP_IoTruncate(void *Ctx, int File, uint64 Len)
{
    static uint8 copy[512];
    char         path[OS_MAX_PATH_LEN];
    char         temp[OS_MAX_PATH_LEN + 4]; /* room for ".cut", so no compiler sees a possible truncation */
    osal_id_t    in;
    osal_id_t    out;
    int32        rc = 0;

    (void)Ctx;
    PP_IoPath(File, path, sizeof(path));
    if (strlen(path) + 4 >= OS_MAX_PATH_LEN)
    {
        return -1; /* the copy's name would be past OSAL's path limit */
    }
    snprintf(temp, sizeof(temp), "%s.cut", path);
    if (OS_OpenCreate(&in, path, OS_FILE_FLAG_NONE, OS_READ_ONLY) != OS_SUCCESS)
    {
        return -1;
    }
    if (OS_OpenCreate(&out, temp, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY) != OS_SUCCESS)
    {
        OS_close(in);
        return -1;
    }
    while (Len > 0 && rc == 0)
    {
        size_t want = (Len < sizeof(copy)) ? (size_t)Len : sizeof(copy);
        int32  n    = OS_read(in, copy, want);
        if (n <= 0 || OS_write(out, copy, (size_t)n) != n)
        {
            rc = -1;
        }
        else
        {
            Len -= (uint64)n;
        }
    }
    OS_close(in);
    OS_close(out);
    if (rc == 0 && OS_rename(temp, path) != OS_SUCCESS)
    {
        rc = -1;
    }
    return rc;
}

static const PP_RunIo_t PP_Io = {NULL, PP_IoOpen, PP_IoWrite, PP_IoRead, PP_IoClose, PP_IoSize, PP_IoTruncate};

static void PRISMPATH_APP_SaveState(void)
{
    if (PRISMPATH_APP_Data.HaveCds)
    {
        int32 Status = CFE_ES_CopyToCDS(PRISMPATH_APP_Data.CdsHandle, &PRISMPATH_APP_Data.Run);
        if (Status != CFE_SUCCESS)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP could not save the run state to the CDS, rc=0x%08X",
                              (unsigned int)Status);
        }
    }
}

/* The run state: restored from the Critical Data Store after a processor reset, else begun fresh. A restored
 * state holds the run's files to the lengths it recorded. */
static void PRISMPATH_APP_InitState(void)
{
    int32 Status;
    bool  Restored = false;

    (void)OS_mkdir(PRISMPATH_APP_PLATFORM_RUN_DIR, 0);
    Status = CFE_ES_RegisterCDS(&PRISMPATH_APP_Data.CdsHandle, sizeof(PP_RunState_t), PRISMPATH_APP_PLATFORM_CDS_NAME);
    if (Status == CFE_ES_CDS_ALREADY_EXISTS)
    {
        PRISMPATH_APP_Data.HaveCds = true;
        if (CFE_ES_RestoreFromCDS(&PRISMPATH_APP_Data.Run, PRISMPATH_APP_Data.CdsHandle) == CFE_SUCCESS &&
            PP_Run_StateValid(&PRISMPATH_APP_Data.Run))
        {
            Restored = true;
        }
        else
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP the CDS run state does not read; a new run begins");
        }
    }
    else if (Status == CFE_SUCCESS)
    {
        PRISMPATH_APP_Data.HaveCds = true;
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no CDS (rc=0x%08X): the run and the version floor will not survive a reset",
                          (unsigned int)Status);
    }

    if (Restored)
    {
        if (PP_Run_Recover(&PRISMPATH_APP_Data.Run, &PP_Io) != 0)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP a run file is shorter than the CDS records; the run will not verify");
        }
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP RUN RESTORED from CDS receipts=%u floor=v%u cases=%u",
                          (unsigned int)PRISMPATH_APP_Data.Run.Acc.count,
                          (unsigned int)PRISMPATH_APP_Data.Run.FloorVersion, (unsigned int)PRISMPATH_APP_Data.Run.CaseCount);
    }
    else
    {
        PP_Run_Init(&PRISMPATH_APP_Data.Run);
        if (PP_Run_Begin(&PP_Io) != 0)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP could not create the run files under %s", PRISMPATH_APP_PLATFORM_RUN_DIR);
        }
        PRISMPATH_APP_SaveState();
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP RUN BEGUN receipts=0 floor=v0");
    }
}

static bool PRISMPATH_APP_ReadKey(const char *Path, uint8 *Out, size_t Len)
{
    osal_id_t fd;
    int32     n;

    if (OS_OpenCreate(&fd, Path, OS_FILE_FLAG_NONE, OS_READ_ONLY) != OS_SUCCESS)
    {
        return false;
    }
    n = OS_read(fd, Out, Len);
    OS_close(fd);
    return n == (int32)Len;
}

static void PRISMPATH_APP_LoadKeys(void)
{
    uint8 seed[32];

    PRISMPATH_APP_Data.Keys.HaveAuthority =
        PRISMPATH_APP_ReadKey(PRISMPATH_APP_PLATFORM_AUTHORITY_FILE, PRISMPATH_APP_Data.Keys.AuthorityPub, 32);
    if (!PRISMPATH_APP_Data.Keys.HaveAuthority)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_KEY_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no authority key at %s: every image is refused (sig:missing)",
                          PRISMPATH_APP_PLATFORM_AUTHORITY_FILE);
    }
    if (PRISMPATH_APP_ReadKey(PRISMPATH_APP_PLATFORM_INSTANCE_FILE, seed, sizeof(seed)))
    {
        PP_Run_SetInstanceSeed(&PRISMPATH_APP_Data.Keys, seed);
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_KEY_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no instance key at %s: decisions are receipted but no root can be signed",
                          PRISMPATH_APP_PLATFORM_INSTANCE_FILE);
    }
    memset(seed, 0, sizeof(seed));
}

/* Every check a table must pass before it decides: the kernel's structural checks, then the authority's
 * signatures and the version floor. Returns 0 or the registered cause; Digest is the table's. */
static int PRISMPATH_APP_Gate(const PP_PolicyTable_t *Table, uint8 Digest[32])
{
    int rc = PP_Kernel_Check(Table);

    if (rc == 0)
    {
        rc = PP_Run_CheckTable(&PRISMPATH_APP_Data.Run, &PRISMPATH_APP_Data.Keys, Table, Digest);
    }
    return rc;
}

/* ----------------------------------------------------------------- the policy table */
int32 PRISMPATH_APP_TblValidationFunc(void *TblData)
{
    uint8 Digest[32];
    int   rc = PRISMPATH_APP_Gate((const PP_PolicyTable_t *)TblData, Digest);

    if (rc != 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%d (validation); the active image is unchanged", rc);
        return -1;
    }
    return CFE_SUCCESS;
}

/* Take the table's active image into the kernel. The kernel checks it again, so an image that reached the
 * active buffer by a path that skipped the validation command still never decides. */
static void PRISMPATH_APP_ActivateFromTable(void)
{
    PP_PolicyTable_t *Table = NULL;
    int               rc;
    unsigned int      Rules   = 0;
    unsigned int      Version = 0;
    uint8             Digest[32];

    if (CFE_TBL_GetAddress((void **)&Table, PRISMPATH_APP_Data.TblHandle) < CFE_SUCCESS)
    {
        return;
    }
    rc = PRISMPATH_APP_Gate(Table, Digest);
    if (rc == 0)
    {
        rc = PP_Kernel_Activate(Table);
    }
    if (rc == 0)
    {
        PRISMPATH_APP_Data.Active = *Table;
        memcpy(PRISMPATH_APP_Data.ActiveDigest, Digest, sizeof(Digest));
        PP_Run_Accept(&PRISMPATH_APP_Data.Run, Table->Version, Digest);
        PRISMPATH_APP_SaveState();
        Rules   = Table->RuleCount;
        Version = Table->Version;
    }
    CFE_TBL_ReleaseAddress(PRISMPATH_APP_Data.TblHandle);
    if (rc == 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesLoaded++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_LOADED_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP POLICY LOADED v%u layout=0x%08X rules=%u", Version,
                          (unsigned int)PP_Kernel_LayoutHash(), Rules);
    }
    else
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%d (activation); the active image is unchanged", rc);
    }
    PRISMPATH_APP_Data.HkTlm.Payload.PolicyActive = (uint8)PP_Kernel_Active();
}

static void PRISMPATH_APP_ManageTable(void)
{
    int32 Status = CFE_TBL_Manage(PRISMPATH_APP_Data.TblHandle);

    if (Status == CFE_TBL_INFO_UPDATED)
    {
        PRISMPATH_APP_ActivateFromTable();
    }
}

/* ----------------------------------------------------------------- one proposed command */
static void PRISMPATH_APP_Forward(PRISMPATH_APP_ProposedCmd_t *Proposed, uint32 Seq)
{
    CFE_MSG_FcnCode_t Fc = 0;
    int32             Status;

    PRISMPATH_APP_Data.VehicleCmd = *Proposed;
    (void)CFE_MSG_SetMsgId(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), PRISMPATH_APP_Data.VehicleMid);
    (void)CFE_MSG_GetFcnCode(CFE_MSG_PTR(Proposed->CommandHeader), &Fc);
    (void)CFE_MSG_SetFcnCode(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), Fc);
    (void)CFE_MSG_GenerateChecksum(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader));
    Status = CFE_SB_TransmitMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), true);
    if (Status == CFE_SUCCESS)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.Forwarded++;
    }
    else
    {
        PRISMPATH_APP_Data.HkTlm.Payload.ForwardErrors++;
        CFE_EVS_SendEvent(PRISMPATH_APP_FORWARD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP FORWARD ERROR seq=%u rc=0x%08X", (unsigned int)Seq, (unsigned int)Status);
    }
}

static void PRISMPATH_APP_Proposal(const CFE_SB_Buffer_t *SBBufPtr)
{
    PRISMPATH_APP_ProposedCmd_t Proposed;
    PP_Verdict_t                Verdict;
    CFE_MSG_Size_t              Size = 0;
    size_t                      PayloadLen;
    uint32                      Seq;

    (void)CFE_MSG_GetSize(&SBBufPtr->Msg, &Size);
    PayloadLen = (Size > sizeof(CFE_MSG_CommandHeader_t)) ? (Size - sizeof(CFE_MSG_CommandHeader_t)) : 0;
    memset(&Proposed, 0, sizeof(Proposed));
    memcpy(&Proposed, SBBufPtr, (Size < sizeof(Proposed)) ? Size : sizeof(Proposed));

    const uint8                *Payload = &((const uint8 *)&Proposed)[sizeof(CFE_MSG_CommandHeader_t)];
    uint64                      Receipt = 0;
    char                        Rcpt[24];

    Seq = ++PRISMPATH_APP_Data.HkTlm.Payload.Proposed;
    if (PayloadLen > PRISMPATH_APP_PAYLOAD_LEN)
    {
        PayloadLen = PRISMPATH_APP_PAYLOAD_LEN;
    }
    CFE_ES_PerfLogEntry(PRISMPATH_APP_DECIDE_PERF_ID);
    PP_Kernel_Decide(Payload, PayloadLen, &Verdict);
    CFE_ES_PerfLogExit(PRISMPATH_APP_DECIDE_PERF_ID);

    /* the receipt, before anything is acted on; with no image there is nothing to bind it to */
    if (!PP_Kernel_Active())
    {
        PRISMPATH_APP_Data.HkTlm.Payload.Unreceipted++;
        snprintf(Rcpt, sizeof(Rcpt), "none");
    }
    else if (PP_Run_Record(&PRISMPATH_APP_Data.Run, &PP_Io, &PRISMPATH_APP_Data.Keys, &PRISMPATH_APP_Data.Active,
                           PRISMPATH_APP_Data.ActiveDigest, Payload, PayloadLen, &Verdict, &Receipt) == 0)
    {
        PRISMPATH_APP_SaveState();
        snprintf(Rcpt, sizeof(Rcpt), "%u", (unsigned int)Receipt);
    }
    else
    {
        PRISMPATH_APP_Data.HkTlm.Payload.RecordErrors++;
        CFE_EVS_SendEvent(PRISMPATH_APP_RECORD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP RECORD ERROR seq=%u: the decision could not be receipted and is not acted on",
                          (unsigned int)Seq);
        if (Verdict.Kind == PP_KIND_ALLOW)
        {
            PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
            return; /* an allow nobody can audit is not carried out */
        }
        snprintf(Rcpt, sizeof(Rcpt), "none");
    }

    switch (Verdict.Kind)
    {
        case PP_KIND_ALLOW:
            PRISMPATH_APP_Data.HkTlm.Payload.Allowed++;
            CFE_EVS_SendEvent(PRISMPATH_APP_ALLOW_EID, CFE_EVS_EventType_INFORMATION,
                              "PRISMPATH_APP ALLOW seq=%u rule=%d receipt=%s", (unsigned int)Seq, (int)Verdict.Rule,
                              Rcpt);
            PRISMPATH_APP_Forward(&Proposed, Seq);
            break;
        case PP_KIND_ESCALATE:
            PRISMPATH_APP_Data.HkTlm.Payload.Escalated++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Verdict.Cause;
            CFE_EVS_SendEvent(PRISMPATH_APP_ESCALATE_EID, CFE_EVS_EventType_CRITICAL,
                              "PRISMPATH_APP ESCALATE seq=%u rule=%d cause=%u receipt=%s", (unsigned int)Seq,
                              (int)Verdict.Rule, (unsigned int)Verdict.Cause, Rcpt);
            break;
        default:
            PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Verdict.Cause;
            if (Verdict.Rule >= 0)
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u rule=%d cause=%u receipt=%s", (unsigned int)Seq,
                                  (int)Verdict.Rule, (unsigned int)Verdict.Cause, Rcpt);
            }
            else
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u core cause=%u field=%s receipt=%s", (unsigned int)Seq,
                                  (unsigned int)Verdict.Cause, PP_Kernel_FieldName(Verdict.Field), Rcpt);
            }
            break;
    }
}

/* ----------------------------------------------------------------- housekeeping and ground commands */
static void PRISMPATH_APP_SendHk(void)
{
    PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;

    uint8                          Root[32];

    Hk->PolicyActive     = (uint8)PP_Kernel_Active();
    Hk->PolicyLayoutHash = PP_Kernel_LayoutHash();
    Hk->ReceiptCount     = (uint32)PP_Run_Root(&PRISMPATH_APP_Data.Run, Root);
    Hk->PolicyVersion    = PRISMPATH_APP_Data.Run.FloorVersion;
    Hk->Seals            = (uint32)PRISMPATH_APP_Data.Run.Seals;
    memcpy(Hk->Root, Root, sizeof(Hk->Root));
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader), true);
    CFE_EVS_SendEvent(PRISMPATH_APP_HK_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP HK proposed=%u allowed=%u refused=%u escalated=%u forwarded=%u active=%u "
                      "receipts=%u floor=v%u",
                      (unsigned int)Hk->Proposed, (unsigned int)Hk->Allowed, (unsigned int)Hk->Refused,
                      (unsigned int)Hk->Escalated, (unsigned int)Hk->Forwarded, (unsigned int)Hk->PolicyActive,
                      (unsigned int)Hk->ReceiptCount, (unsigned int)Hk->PolicyVersion);
}

static bool PRISMPATH_APP_VerifyLength(const CFE_MSG_Message_t *MsgPtr, size_t Expected)
{
    CFE_MSG_Size_t Actual = 0;

    (void)CFE_MSG_GetSize(MsgPtr, &Actual);
    if (Actual != Expected)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.CommandErrorCounter++;
        CFE_EVS_SendEvent(PRISMPATH_APP_CMD_LEN_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP invalid command length %u, expected %u", (unsigned int)Actual,
                          (unsigned int)Expected);
        return false;
    }
    return true;
}


/* Sign a root statement over every receipt and write the run for downlink. */
static void PRISMPATH_APP_Seal(void)
{
    CFE_TIME_SysTime_t Now = CFE_TIME_GetTime();
    uint64             TimeUs;
    uint8              Root[32];
    char               Hex[65];
    uint32             Leaves;
    int                rc;
    int                i;

    /* the spacecraft clock (cFE time, TAI since the mission epoch) in microseconds */
    TimeUs = (uint64)Now.Seconds * 1000000u + CFE_TIME_Sub2MicroSecs(Now.Subseconds);
    rc     = PP_Run_Seal(&PRISMPATH_APP_Data.Run, &PP_Io, &PRISMPATH_APP_Data.Keys, TimeUs);
    if (rc != 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.CommandErrorCounter++;
        if (rc <= PP_SEAL_FILE_ERR(0) && rc > PP_SEAL_FILE_ERR(PP_FILE_COUNT))
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_SEAL_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP SEAL FAILED: %s/%s could not be read or written",
                              PRISMPATH_APP_PLATFORM_RUN_DIR, PP_RunFileNames[PP_SEAL_FILE_ERR(0) - rc]);
        }
        else
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_SEAL_ERR_EID, CFE_EVS_EventType_ERROR, "PRISMPATH_APP SEAL FAILED: %s",
                              rc == -2 ? "no instance or authority key is loaded" : "a document did not fit its buffer");
        }
        return;
    }
    PRISMPATH_APP_SaveState();
    PRISMPATH_APP_Data.HkTlm.Payload.CommandCounter++;
    Leaves = (uint32)PP_Run_Root(&PRISMPATH_APP_Data.Run, Root);
    for (i = 0; i < 32; i++)
    {
        snprintf(&Hex[2 * i], 3, "%02x", Root[i]);
    }
    CFE_EVS_SendEvent(PRISMPATH_APP_SEALED_EID, CFE_EVS_EventType_INFORMATION, "PRISMPATH_APP SEALED receipts=%u root=%s",
                      (unsigned int)Leaves, Leaves ? Hex : "-");
}

static void PRISMPATH_APP_GroundCommand(const CFE_SB_Buffer_t *SBBufPtr)
{
    CFE_MSG_FcnCode_t Cc = 0;

    (void)CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &Cc);
    switch (Cc)
    {
        case PRISMPATH_APP_NOOP_CC:
            if (PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(PRISMPATH_APP_NoopCmd_t)))
            {
                PRISMPATH_APP_Data.HkTlm.Payload.CommandCounter++;
                CFE_EVS_SendEvent(PRISMPATH_APP_NOOP_INF_EID, CFE_EVS_EventType_INFORMATION, "PRISMPATH_APP NOOP");
            }
            break;
        case PRISMPATH_APP_RESET_COUNTERS_CC:
            if (PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(PRISMPATH_APP_ResetCountersCmd_t)))
            {
                PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;
                Hk->CommandCounter = 0;
                Hk->CommandErrorCounter = 0;
                Hk->Proposed = Hk->Allowed = Hk->Refused = Hk->Escalated = 0;
                Hk->Forwarded = Hk->ForwardErrors = Hk->LastRefusalCause = 0;
                CFE_EVS_SendEvent(PRISMPATH_APP_RESET_INF_EID, CFE_EVS_EventType_INFORMATION,
                                  "PRISMPATH_APP counters reset");
            }
            break;
        case PRISMPATH_APP_SEAL_CC:
            if (PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(PRISMPATH_APP_SealCmd_t)))
            {
                PRISMPATH_APP_Seal();
            }
            break;
        default:
            PRISMPATH_APP_Data.HkTlm.Payload.CommandErrorCounter++;
            CFE_EVS_SendEvent(PRISMPATH_APP_CC_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP invalid ground command code %d", (int)Cc);
            break;
    }
}

static void PRISMPATH_APP_TaskPipe(const CFE_SB_Buffer_t *SBBufPtr)
{
    CFE_SB_MsgId_t MsgId = CFE_SB_INVALID_MSG_ID;

    (void)CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);
    if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.ProposedMid))
    {
        PRISMPATH_APP_Proposal(SBBufPtr);
    }
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.SendHkMid))
    {
        PRISMPATH_APP_SendHk();
    }
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.CmdMid))
    {
        PRISMPATH_APP_GroundCommand(SBBufPtr);
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_MID_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP invalid message id 0x%x", (unsigned int)CFE_SB_MsgIdToValue(MsgId));
    }
}

/* ----------------------------------------------------------------- entry point and initialization */
void PRISMPATH_APP_Main(void)
{
    CFE_Status_t     Status;
    CFE_SB_Buffer_t *SBBufPtr;

    CFE_ES_PerfLogEntry(PRISMPATH_APP_PERF_ID);

    Status = PRISMPATH_APP_Init();
    if (Status != CFE_SUCCESS)
    {
        PRISMPATH_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
    }

    while (CFE_ES_RunLoop(&PRISMPATH_APP_Data.RunStatus) == true)
    {
        CFE_ES_PerfLogExit(PRISMPATH_APP_PERF_ID);
        Status = CFE_SB_ReceiveBuffer(&SBBufPtr, PRISMPATH_APP_Data.CommandPipe, PRISMPATH_APP_PLATFORM_TABLE_POLL_MS);
        CFE_ES_PerfLogEntry(PRISMPATH_APP_PERF_ID);

        /* a ground table load, validate and activate is picked up here, between messages */
        PRISMPATH_APP_ManageTable();

        if (Status == CFE_SUCCESS)
        {
            PRISMPATH_APP_TaskPipe(SBBufPtr);
        }
        else if (Status != CFE_SB_TIME_OUT)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP SB pipe read error 0x%08X, app will exit", (unsigned int)Status);
            PRISMPATH_APP_Data.RunStatus = CFE_ES_RunStatus_APP_ERROR;
        }
    }

    CFE_ES_PerfLogExit(PRISMPATH_APP_PERF_ID);
    CFE_ES_ExitApp(PRISMPATH_APP_Data.RunStatus);
}

/* The software bus queues at most MsgLim messages of one id on a pipe, and drops the rest with an event. The
 * default is 4, which a burst of proposals from one ingest cycle exceeds, so each id gets the whole pipe. */
static CFE_Status_t PRISMPATH_APP_Subscribe(CFE_SB_MsgId_t Mid)
{
    CFE_Status_t Status = CFE_SB_SubscribeEx(Mid, PRISMPATH_APP_Data.CommandPipe, CFE_SB_DEFAULT_QOS,
                                             PRISMPATH_APP_PLATFORM_PIPE_DEPTH);

    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_SUB_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error subscribing to 0x%x, rc=0x%08X",
                          (unsigned int)CFE_SB_MsgIdToValue(Mid), (unsigned int)Status);
    }
    return Status;
}

CFE_Status_t PRISMPATH_APP_Init(void)
{
    CFE_Status_t Status;

    memset(&PRISMPATH_APP_Data, 0, sizeof(PRISMPATH_APP_Data));
    PRISMPATH_APP_Data.RunStatus   = CFE_ES_RunStatus_APP_RUN;
    PRISMPATH_APP_Data.CmdMid      = CFE_SB_ValueToMsgId(PRISMPATH_APP_CMD_MID);
    PRISMPATH_APP_Data.SendHkMid   = CFE_SB_ValueToMsgId(PRISMPATH_APP_SEND_HK_MID);
    PRISMPATH_APP_Data.ProposedMid = CFE_SB_ValueToMsgId(PRISMPATH_APP_PROPOSED_CMD_MID);
    PRISMPATH_APP_Data.VehicleMid  = CFE_SB_ValueToMsgId(PRISMPATH_APP_VEHICLE_CMD_MID);

    Status = CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);
    if (Status != CFE_SUCCESS)
    {
        CFE_ES_WriteToSysLog("PRISMPATH_APP: error registering events, RC = 0x%08lX\n", (unsigned long)Status);
        return Status;
    }

    CFE_MSG_Init(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader), CFE_SB_ValueToMsgId(PRISMPATH_APP_HK_TLM_MID),
                 sizeof(PRISMPATH_APP_Data.HkTlm));
    CFE_MSG_Init(CFE_MSG_PTR(PRISMPATH_APP_Data.VehicleCmd.CommandHeader), PRISMPATH_APP_Data.VehicleMid,
                 sizeof(PRISMPATH_APP_Data.VehicleCmd));

    Status = CFE_SB_CreatePipe(&PRISMPATH_APP_Data.CommandPipe, PRISMPATH_APP_PLATFORM_PIPE_DEPTH,
                               PRISMPATH_APP_PLATFORM_PIPE_NAME);
    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_CR_PIPE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error creating pipe, RC = 0x%08lX", (unsigned long)Status);
        return Status;
    }

    /* the proposed command id is subscribed here and nowhere else, and the vehicle id only ever published */
    if (PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.SendHkMid) != CFE_SUCCESS ||
        PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.CmdMid) != CFE_SUCCESS ||
        PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.ProposedMid) != CFE_SUCCESS)
    {
        return CFE_SB_BAD_ARGUMENT;
    }

    /* the run state and the keys come first: the initial table load is checked against the floor they hold */
    PRISMPATH_APP_InitState();
    PRISMPATH_APP_LoadKeys();

    Status = CFE_TBL_Register(&PRISMPATH_APP_Data.TblHandle, "PolicyTable", sizeof(PRISMPATH_APP_PolicyTable_t),
                              CFE_TBL_OPT_DEFAULT, PRISMPATH_APP_TblValidationFunc);
    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_TABLE_REG_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error registering the policy table, RC = 0x%08lX", (unsigned long)Status);
        return Status;
    }

    /* The initial load. A refused image leaves the kernel with no policy, which refuses every proposal: the
     * app fails closed, and says so in an event. */
    Status = CFE_TBL_Load(PRISMPATH_APP_Data.TblHandle, CFE_TBL_SRC_FILE, PRISMPATH_APP_PLATFORM_TABLE_FILE);
    if (Status == CFE_SUCCESS || Status == CFE_TBL_INFO_UPDATED)
    {
        PRISMPATH_APP_ActivateFromTable();
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY NOT LOADED rc=0x%08X; every proposal will be refused",
                          (unsigned int)Status);
    }

    CFE_EVS_SendEvent(PRISMPATH_APP_INIT_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP initialized, policy %s, %s reset, receipts=%u", PP_Kernel_Active() ? "active" : "NOT active",
                      CFE_ES_GetResetType(NULL) == CFE_PSP_RST_TYPE_PROCESSOR ? "processor" : "power on",
                      (unsigned int)PRISMPATH_APP_Data.Run.Acc.count);
    return CFE_SUCCESS;
}
