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
 * is never acted on. A SEAL ground command signs a root statement onboard and writes the run, in the layout
 * `prismpath evidence verify` reads, under RUN_DIR.
 *
 * The app is an enforcement point of policy distribution (prismpath_app_dist.h). A table is admitted by its
 * distribution envelope, offered on the software bus in the frames of the frame binding on the app's command topic
 * (PRISMPATH_APP_OFFER_CC, PRISMPATH_APP_CHUNK_CC, PRISMPATH_APP_CONTROL_CC). A commit loads the assembled table with
 * CFE_TBL_Load from its address, so it passes through the table service and the validation callback, which holds it
 * to the commit the C core of distribution is about to make, and the core commits only once the table service took
 * it. The floor of section 6, the trust store with its time floor and the anchor live in the Critical Data Store
 * with the run, so a processor reset continues the run and refuses an older release; a store that does not read
 * loses the floor, and the mission's lost floor response decides what follows. Every state record goes to the
 * ground in housekeeping. All storage is static; nothing is allocated after initialization.
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
_Static_assert(PAYLOAD_OFFSET(MonitorOk) == 6, "monitor_ok offset");
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

PP_AppDist_t PRISMPATH_APP_Dist;
#define DIST (&PRISMPATH_APP_Dist)

_Static_assert(sizeof(((PRISMPATH_APP_HkTlm_Payload_t *)0)->StateRecord) >= PP_RECORD_MAX, "a state record fits HK");
_Static_assert(PRISMPATH_APP_FRAME_MAX == PP_FRAME_LIMIT, "a command carries a frame of the link's limit");

/* ----------------------------------------------------------------- the enforcement point's stores */
static int PP_SaveRecord(void *Ctx)
{
    (void)Ctx;
    if (!PRISMPATH_APP_Data.HaveCds || CFE_ES_CopyToCDS(PRISMPATH_APP_Data.CdsHandle, &DIST->Record) != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP could not save the run and the floor to the CDS");
        return -1;
    }
    return 0;
}

static int PP_SaveCopy(void *Ctx)
{
    (void)Ctx;
    if (!PRISMPATH_APP_Data.HaveCopy || CFE_ES_CopyToCDS(PRISMPATH_APP_Data.CopyHandle, &DIST->Copy) != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP could not save the second copy of the install record to the CDS");
        return -1;
    }
    return 0;
}

/* a file replaced whole: written beside it, then renamed over it, so a reset leaves the old one or the new one (C4) */
static int PP_WriteFile(void *Ctx, const char *Name, const void *Data, size_t Len)
{
    char      path[OS_MAX_PATH_LEN];
    char      temp[OS_MAX_PATH_LEN + 4];
    osal_id_t fd;
    int       rc;

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", PRISMPATH_APP_PLATFORM_DIST_DIR, Name);
    snprintf(temp, sizeof(temp), "%s.new", path);
    if (OS_OpenCreate(&fd, temp, OS_FILE_FLAG_CREATE | OS_FILE_FLAG_TRUNCATE, OS_WRITE_ONLY) != OS_SUCCESS)
    {
        return -1;
    }
    rc = (Len == 0 || OS_write(fd, Data, Len) == (int32)Len) ? 0 : -1;
    OS_close(fd);
    if (rc == 0 && OS_rename(temp, path) != OS_SUCCESS)
    {
        rc = -1;
    }
    if (rc != 0)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR, "PRISMPATH_APP could not write %s", path);
    }
    return rc;
}

static int32 PP_ReadPath(const char *Path, void *Data, size_t Cap)
{
    osal_id_t fd;
    int32     n;
    int32     total = 0;

    if (OS_OpenCreate(&fd, Path, OS_FILE_FLAG_NONE, OS_READ_ONLY) != OS_SUCCESS)
    {
        return -1;
    }
    while ((size_t)total < Cap && (n = OS_read(fd, (uint8 *)Data + total, Cap - (size_t)total)) > 0)
    {
        total += n;
    }
    OS_close(fd);
    return total;
}

static int32 PP_ReadFile(void *Ctx, const char *Name, void *Data, size_t Cap)
{
    char path[OS_MAX_PATH_LEN];

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", PRISMPATH_APP_PLATFORM_DIST_DIR, Name);
    return PP_ReadPath(path, Data, Cap);
}

/* the switch: the whole table through the table service, whose validation callback is PRISMPATH_APP_TblValidationFunc */
static int PP_LoadTable(void *Ctx, const PP_PolicyTable_t *Table)
{
    int32 Status;

    (void)Ctx;
    Status = CFE_TBL_Load(PRISMPATH_APP_Data.TblHandle, CFE_TBL_SRC_ADDRESS, Table);
    if (Status != CFE_SUCCESS && Status != CFE_TBL_INFO_UPDATED)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_DIST_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP TABLE SERVICE refused the table, rc=0x%08X; the release stays staged",
                          (unsigned int)Status);
        return -1;
    }
    return 0;
}

static uint32 PP_NowMs(void)
{
    CFE_TIME_SysTime_t Met = CFE_TIME_GetMET();

    return Met.Seconds * 1000u + CFE_TIME_Sub2MicroSecs(Met.Subseconds) / 1000u;
}

/* the app's time, which envelopes are held to: Unix seconds */
static long long PP_Now(void)
{
    return (long long)CFE_TIME_GetUTC().Seconds + PRISMPATH_APP_PLATFORM_EPOCH_UNIX;
}

static void PRISMPATH_APP_SendHk(void);

static const char *const k_Events[] = {"beat", "staged", "refused", "committed", "aborted", "trust-applied", "lapsed",
                                       "rolled-back", "provisioned", "held", "fallback", "install-applied",
                                       "install-widened", "answered"};

static void PRISMPATH_APP_SendRecord(const uint8 *Record, size_t Len)
{
    PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;

    memcpy(Hk->StateRecord, Record, Len);
    Hk->StateRecordLen = (uint16)Len;
    PRISMPATH_APP_SendHk();
}

static void PRISMPATH_APP_Forward(PRISMPATH_APP_ProposedCmd_t *Proposed, uint32 Seq);

/* OP3: an answer `allow` whose operator case is written carries out the request it answers as it was asked: the
 * payload the escalation kept, with the function code and size its command was proposed with, on the vehicle message
 * id as an allowed proposal is. A kept command this app cannot send as it was asked, proposed on another message id
 * or with a size the command does not hold, is not carried out. */
static void PRISMPATH_APP_NotEnacted(const char *Why)
{
    PRISMPATH_APP_Data.HkTlm.Payload.NotEnacted++;
    CFE_EVS_SendEvent(PRISMPATH_APP_NOT_ENACTED_EID, CFE_EVS_EventType_ERROR,
                      "PRISMPATH_APP NOT ENACTED basis=operator: %s, so the answer allow is not carried out", Why);
}

static void PRISMPATH_APP_Enact(const PP_AppStep_t *Step)
{
    PRISMPATH_APP_ProposedCmd_t Request;
    const PP_AppCommand_t      *Command = &Step->AnswerCommand;
    size_t                      Room    = sizeof(Request) - sizeof(CFE_MSG_CommandHeader_t);

    if (!CFE_SB_MsgId_Equal(CFE_SB_ValueToMsgId((CFE_SB_MsgId_Atom_t)Command->MsgId), PRISMPATH_APP_Data.ProposedMid) ||
        Command->Size < sizeof(CFE_MSG_CommandHeader_t) || Command->Size > sizeof(Request))
    {
        PRISMPATH_APP_NotEnacted("the command its escalation kept is not one this app was proposed");
        return;
    }
    memset(&Request, 0, sizeof(Request));
    CFE_MSG_Init(CFE_MSG_PTR(Request.CommandHeader), PRISMPATH_APP_Data.ProposedMid, Command->Size);
    (void)CFE_MSG_SetFcnCode(CFE_MSG_PTR(Request.CommandHeader), Command->FcnCode);
    memcpy(&((uint8 *)&Request)[sizeof(CFE_MSG_CommandHeader_t)], Step->AnswerRequest,
           Step->AnswerRequestLen < Room ? Step->AnswerRequestLen : Room);
    PRISMPATH_APP_Data.HkTlm.Payload.Allowed++;
    PRISMPATH_APP_Forward(&Request, PRISMPATH_APP_Data.HkTlm.Payload.Proposed);
}

/* Every state record a step made, each in a housekeeping packet with an event, then the events of what it did. */
static void PRISMPATH_APP_Report(void)
{
    const PP_AppStep_t *Step = &DIST->Step;
    size_t              k;
    char                hex[65];
    int                 i;

    for (k = 0; k < Step->N; k++)
    {
        const uint8 *r = Step->Record[k];
        CFE_EVS_SendEvent(PRISMPATH_APP_DIST_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP DIST %s cause=%u status=0x%02X active_seq=%u floor=%u",
                          r[5] < sizeof(k_Events) / sizeof(k_Events[0]) ? k_Events[r[5]] : "?", (unsigned int)r[7],
                          (unsigned int)r[6], (unsigned int)(r[96] | r[97] << 8 | r[98] << 16 | (uint32)r[99] << 24),
                          (unsigned int)(r[104] | r[105] << 8 | r[106] << 16 | (uint32)r[107] << 24));
        PRISMPATH_APP_SendRecord(r, Step->Len[k]);
    }
    if (Step->Provisioned)
    {
        for (i = 0; i < 32; i++)
        {
            snprintf(&hex[2 * i], 3, "%02x", Step->Fingerprint[i]);
        }
        CFE_EVS_SendEvent(PRISMPATH_APP_PROVISIONED_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP PROVISIONED anchor %s", hex);
        for (k = 0; k < PP_SETS; k++)
        {
            static const char *const kinds[PP_SETS] = {"floor", "fallback", "ceiling"};
            if (DIST->Pep.d.has_install && DIST->Pep.d.install.sets[k].held)
            {
                for (i = 0; i < 32; i++)
                {
                    snprintf(&hex[2 * i], 3, "%02x", DIST->Pep.d.install.sets[k].envelope_id[i]);
                }
                CFE_EVS_SendEvent(PRISMPATH_APP_PROVISIONED_EID, CFE_EVS_EventType_INFORMATION,
                                  "PRISMPATH_APP PROVISIONED install.%s %s", kinds[k], hex);
            }
        }
    }
    if (Step->HoldBegan || Step->HoldEnded)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_HELD_EID, CFE_EVS_EventType_CRITICAL,
                          Step->HoldBegan ? "PRISMPATH_APP HELD: the release expired and the mission holds at expiry; it "
                                            "keeps deciding, every record and receipt marked held (dist:held)"
                                          : "PRISMPATH_APP HOLD ENDED");
    }
    if (Step->Locked)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP FLOOR LOST: no release is admitted and every proposal is refused until ground "
                          "deletes the CDS %s and restarts the app", PRISMPATH_APP_PLATFORM_CDS_NAME);
    }
    if (Step->FloorAt)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP FLOOR LOST: releases from seq %u up are admitted",
                          (unsigned int)PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_SEQ);
    }
    if (Step->TableCause != 0 || Step->TableBusy)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%u (switch); the active table is unchanged",
                          (unsigned int)Step->TableCause);
    }
    if (Step->Answered)
    {
        char hex[33];
        for (i = 0; i < 16; i++)
        {
            snprintf(&hex[2 * i], 3, "%02x", Step->AnswerReceipt[i]);
        }
        /* OP3, OP4, RC4: the answered record is in housekeeping, and the request is receipted in a case of basis
         * operator before an answer `allow` carries it out */
        if (Step->AnswerRecordError)
        {
            PRISMPATH_APP_Data.HkTlm.Payload.RecordErrors++;
        }
        CFE_EVS_SendEvent(PRISMPATH_APP_ANSWERED_EID, CFE_EVS_EventType_CRITICAL,
                          "PRISMPATH_APP ANSWERED %s receipt=%s operator receipt=%u%s",
                          Step->AnswerAllow ? "allow" : "refuse", hex, (unsigned int)Step->AnswerIndex,
                          Step->AnswerReceipted ? "" : ": not receipted, so the request is not carried out");
        if (Step->AnswerEnact)
        {
            PRISMPATH_APP_Enact(Step);
        }
        else if (Step->AnswerNotEnacted)
        {
            PRISMPATH_APP_NotEnacted("its escalation kept no command to carry it out as it was asked, as one kept by "
                                     "an older build, and no function code is guessed");
        }
    }
    if (Step->RunError && DIST->Started)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP an install statement could not be written to %s/install.jsonl; the run will "
                          "not verify", PRISMPATH_APP_PLATFORM_RUN_DIR);
    }
    if (Step->Dropped != 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.FramesDropped++;
        CFE_EVS_SendEvent(PRISMPATH_APP_DIST_ERR_EID, CFE_EVS_EventType_ERROR, "PRISMPATH_APP FRAME DROPPED cause=%u",
                          (unsigned int)Step->Dropped);
    }
    for (k = 0; k < Step->N; k++)
    {
        if (Step->Record[k][5] == PP_EV_COMMITTED || Step->Record[k][5] == PP_EV_ROLLED_BACK)
        {
            PRISMPATH_APP_Data.HkTlm.Payload.PoliciesLoaded++;
            CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_LOADED_EID, CFE_EVS_EventType_INFORMATION,
                              "PRISMPATH_APP POLICY LOADED v%u layout=0x%08X rules=%u", (unsigned int)DIST->Active.Version,
                              (unsigned int)PP_Kernel_LayoutHash(), (unsigned int)DIST->Active.RuleCount);
        }
    }
    PRISMPATH_APP_Data.HkTlm.Payload.PolicyActive = (uint8)PP_Kernel_Active();
}

/* ----------------------------------------------------------------- start */
static uint8 s_Anchor[4096];
static uint8 s_Brought[PP_APP_BROUGHT_MAX][8 + PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 80];
static uint8 s_Boot[PP_APP_BOOT_MAX][8 + PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 80];
static PP_AppDistConfig_t s_Config;

static size_t PRISMPATH_APP_ReadStatements(const char *Pattern, uint8 (*Buf)[8 + PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 80],
                                           PP_AppStatement_t *Out, size_t Max)
{
    size_t n = 0;
    size_t k;

    for (k = 0; k < Max; k++)
    {
        char  path[OS_MAX_PATH_LEN];
        int32 len;
        snprintf(path, sizeof(path), Pattern, (unsigned int)k);
        len = PP_ReadPath(path, Buf[k], sizeof(Buf[k]));
        if (len < 0)
        {
            break;
        }
        if (PP_AppDist_ReadStatement(Buf[k], (size_t)len, &Out[n]) == 0)
        {
            n++;
        }
        else
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_DIST_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP %s is not a statement file", path);
        }
    }
    return n;
}

static bool PRISMPATH_APP_ReadKey(const char *Path, uint8 *Out, size_t Len)
{
    return PP_ReadPath(Path, Out, Len) == (int32)Len;
}

/* the run's keys, which the core run is attested with, and the instance key, which also signs every state record */
static void PRISMPATH_APP_LoadKeys(void)
{
    uint8 seed[32];

    DIST->Keys.HaveAuthority = PRISMPATH_APP_ReadKey(PRISMPATH_APP_PLATFORM_AUTHORITY_FILE, DIST->Keys.AuthorityPub, 32);
    if (!DIST->Keys.HaveAuthority)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_KEY_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no authority key at %s: no table can be attested, so none is committed",
                          PRISMPATH_APP_PLATFORM_AUTHORITY_FILE);
    }
    if (PRISMPATH_APP_ReadKey(PRISMPATH_APP_PLATFORM_INSTANCE_FILE, seed, sizeof(seed)))
    {
        memcpy(s_Config.InstanceSeed, seed, 32);
        PP_Run_SetInstanceSeed(&DIST->Keys, seed);
    }
    else
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_KEY_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no instance key at %s: no state record or root can be signed",
                          PRISMPATH_APP_PLATFORM_INSTANCE_FILE);
    }
    memset(seed, 0, sizeof(seed));
}

/* A Critical Data Store area: what it held, restored into Data. */
static int PRISMPATH_APP_Restore(CFE_ES_CDSHandle_t *Handle, bool *Have, void *Data, size_t Size, const char *Name)
{
    int32 Status = CFE_ES_RegisterCDS(Handle, Size, Name);

    if (Status == CFE_ES_CDS_ALREADY_EXISTS)
    {
        *Have = true;
        return CFE_ES_RestoreFromCDS(Data, *Handle) == CFE_SUCCESS ? PP_APP_STORE_READ : PP_APP_STORE_LOST;
    }
    *Have = Status == CFE_SUCCESS;
    if (!*Have)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP no CDS %s (rc=0x%08X): it will not survive a reset", Name, (unsigned int)Status);
    }
    return PP_APP_STORE_ABSENT;
}

static void PRISMPATH_APP_InitState(void)
{
    int record, copy;
    int32 n;

    (void)OS_mkdir(PRISMPATH_APP_PLATFORM_RUN_DIR, 0);
    (void)OS_mkdir(PRISMPATH_APP_PLATFORM_DIST_DIR, 0);
    DIST->Store = (PP_AppStore_t){NULL, PP_SaveRecord, PP_SaveCopy, PP_WriteFile, PP_ReadFile, PP_LoadTable};
    record = PRISMPATH_APP_Restore(&PRISMPATH_APP_Data.CdsHandle, &PRISMPATH_APP_Data.HaveCds, &DIST->Record,
                                   sizeof(DIST->Record), PRISMPATH_APP_PLATFORM_CDS_NAME);
    if (record == PP_APP_STORE_READ &&
        (DIST->Record.Magic != PP_APP_RECORD_MAGIC || DIST->Record.Size != sizeof(DIST->Record) ||
         !PP_Run_StateValid(&DIST->Record.Run)))
    {
        record = PP_APP_STORE_LOST;
    }
    copy = PRISMPATH_APP_Restore(&PRISMPATH_APP_Data.CopyHandle, &PRISMPATH_APP_Data.HaveCopy, &DIST->Copy,
                                 sizeof(DIST->Copy), PRISMPATH_APP_PLATFORM_COPY_CDS_NAME);
    if (copy == PP_APP_STORE_READ && (DIST->Copy.Magic != PP_APP_COPY_MAGIC || DIST->Copy.Size != sizeof(DIST->Copy)))
    {
        copy = PP_APP_STORE_LOST;
    }
    if (record == PP_APP_STORE_LOST)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP the CDS record does not read, so the floor is lost; a new run begins");
    }
    s_Config.ExpiryResponse = PRISMPATH_APP_PLATFORM_EXPIRY_RESPONSE;
    s_Config.LostFloor      = PRISMPATH_APP_PLATFORM_LOST_FLOOR;
    s_Config.MinSeq         = PRISMPATH_APP_PLATFORM_LOST_FLOOR_MIN_SEQ;
    s_Config.MonitorStale   = PRISMPATH_APP_MONITOR_STALE_SECS;
    n                       = PP_ReadPath(PRISMPATH_APP_PLATFORM_ANCHOR_FILE, s_Anchor, sizeof(s_Anchor));
    s_Config.Anchor         = n > 0 ? s_Anchor : NULL;
    s_Config.AnchorLen      = n > 0 ? (size_t)n : 0u;
    s_Config.NBrought = PRISMPATH_APP_ReadStatements(PRISMPATH_APP_PLATFORM_BRING_FILE, s_Brought, s_Config.Brought,
                                                     PP_APP_BROUGHT_MAX);
    s_Config.NBoot = PRISMPATH_APP_ReadStatements(PRISMPATH_APP_PLATFORM_BOOT_FILE, s_Boot, s_Config.Boot,
                                                  PP_APP_BOOT_MAX);
    PRISMPATH_APP_LoadKeys();

    DIST->Io                       = &PP_Io; /* a new run's files are begun by the start, which writes install.jsonl */
    PRISMPATH_APP_Data.DistStarted = PP_AppDist_Start(DIST, &s_Config, record, copy, PP_NowMs(), PP_Now()) == 0;
    if (!PRISMPATH_APP_Data.DistStarted)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_DIST_ERR_EID, CFE_EVS_EventType_CRITICAL,
                          "PRISMPATH_APP the enforcement point did not start (no anchor, another expiry setting than it "
                          "was provisioned with, or an instance key that is a trusted key): every proposal is refused");
    }
    if (record == PP_APP_STORE_READ)
    {
        if (PP_Run_Recover(&DIST->Record.Run, &PP_Io) != 0)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP a run file is shorter than the CDS records; the run will not verify");
        }
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP RUN RESTORED from CDS receipts=%u floor=%u cases=%u",
                          (unsigned int)DIST->Record.Run.Acc.count, (unsigned int)DIST->Pep.d.floor_seq,
                          (unsigned int)DIST->Record.Run.CaseCount);
    }
    else
    {
        if (DIST->Step.RunError)
        {
            CFE_EVS_SendEvent(PRISMPATH_APP_STATE_ERR_EID, CFE_EVS_EventType_ERROR,
                              "PRISMPATH_APP could not create the run files under %s", PRISMPATH_APP_PLATFORM_RUN_DIR);
        }
        (void)PP_AppDist_SaveRun(DIST);
        CFE_EVS_SendEvent(PRISMPATH_APP_STATE_INF_EID, CFE_EVS_EventType_INFORMATION,
                          "PRISMPATH_APP RUN BEGUN receipts=0 floor=%u%s", (unsigned int)DIST->Pep.d.floor_seq,
                          DIST->Pep.locked ? " locked" : "");
    }
    PRISMPATH_APP_Report();
}

/* ----------------------------------------------------------------- the policy table */
int32 PRISMPATH_APP_TblValidationFunc(void *TblData)
{
    int rc = PP_AppDist_ValidateTable(DIST, (const PP_PolicyTable_t *)TblData);

    if (rc != 0)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.PoliciesRejected++;
        CFE_EVS_SendEvent(PRISMPATH_APP_POLICY_REJECTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP POLICY REJECTED cause=%d (validation): a table is admitted only by its "
                          "distribution envelope, offered on the software bus", rc);
        return -1;
    }
    return CFE_SUCCESS;
}

/* The table service's own housekeeping between messages. What decides is the kernel, which follows the release the
 * enforcement point holds, so a table that reaches the table service by another path never decides. */
static void PRISMPATH_APP_ManageTable(void)
{
    (void)CFE_TBL_Manage(PRISMPATH_APP_Data.TblHandle);
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

/* the runtime monitor's verdict, kept with the time it arrived */
static void PRISMPATH_APP_MonitorVerdict(const CFE_SB_Buffer_t *SBBufPtr)
{
    CFE_MSG_Size_t Size = 0;

    (void)CFE_MSG_GetSize(&SBBufPtr->Msg, &Size);
    if (Size < sizeof(PRISMPATH_APP_MonitorVerdict_t))
    {
        return;
    }
    PRISMPATH_APP_Data.MonitorVerdict = ((const PRISMPATH_APP_MonitorVerdict_t *)SBBufPtr)->Ok ? 1 : 0;
    PRISMPATH_APP_Data.MonitorAt      = (uint32)CFE_TIME_GetMETseconds();
    PRISMPATH_APP_Data.MonitorSeen    = true;
}

/* monitor_ok for the proposal being decided: no monitor in this mission (bound 0) reads true; with one, true only
 * for an ok verdict received within the staleness bound, so no verdict yet, a violation and a silent monitor all
 * read false */
static uint8 PRISMPATH_APP_MonitorOk(void)
{
#if PRISMPATH_APP_MONITOR_STALE_SECS > 0
    uint32 Now = (uint32)CFE_TIME_GetMETseconds();

    return (PRISMPATH_APP_Data.MonitorSeen && PRISMPATH_APP_Data.MonitorVerdict != 0 &&
            (uint32)(Now - PRISMPATH_APP_Data.MonitorAt) <= (uint32)PRISMPATH_APP_MONITOR_STALE_SECS)
               ? 1u
               : 0u;
#else
    return 1u;
#endif
}

/* the age of the monitor's last verdict, which an action floor's freshness test reads (AF10) */
static uint32 PRISMPATH_APP_MonitorAge(void)
{
    return PRISMPATH_APP_Data.MonitorSeen ? (uint32)CFE_TIME_GetMETseconds() - PRISMPATH_APP_Data.MonitorAt
                                          : PP_AGE_NONE;
}

static void PRISMPATH_APP_Proposal(const CFE_SB_Buffer_t *SBBufPtr)
{
    PRISMPATH_APP_ProposedCmd_t Proposed;
    PP_AppDecision_t            Decision;
    CFE_MSG_Size_t              Size = 0;
    size_t                      PayloadLen;
    uint32                      Seq;
    char                        Rcpt[24];
    PP_AppCommand_t             Command;
    CFE_SB_MsgId_t              MsgId = CFE_SB_INVALID_MSG_ID;
    CFE_MSG_FcnCode_t           Fc    = 0;

    (void)CFE_MSG_GetSize(&SBBufPtr->Msg, &Size);
    (void)CFE_MSG_GetMsgId(&SBBufPtr->Msg, &MsgId);
    (void)CFE_MSG_GetFcnCode(&SBBufPtr->Msg, &Fc);
    /* OP3: how it was asked, kept with an escalation so an answer `allow` sends this command and no other */
    Command.MsgId   = (uint32_t)CFE_SB_MsgIdToValue(MsgId);
    Command.FcnCode = (uint8_t)Fc;
    Command.Size    = (uint16_t)(Size > 0xFFFFu ? 0xFFFFu : Size);
    PayloadLen = (Size > sizeof(CFE_MSG_CommandHeader_t)) ? (Size - sizeof(CFE_MSG_CommandHeader_t)) : 0;
    memset(&Proposed, 0, sizeof(Proposed));
    memcpy(&Proposed, SBBufPtr, (Size < sizeof(Proposed)) ? Size : sizeof(Proposed));

    const uint8 *Payload = &((const uint8 *)&Proposed)[sizeof(CFE_MSG_CommandHeader_t)];

    Seq = ++PRISMPATH_APP_Data.HkTlm.Payload.Proposed;
    /* the app's own reading of the monitor, never the proposer's: the byte in the command is overwritten */
    Proposed.MonitorOk = PRISMPATH_APP_MonitorOk();
    PP_Kernel_SetMonitorOk(Proposed.MonitorOk);
    if (PayloadLen > PRISMPATH_APP_PAYLOAD_LEN)
    {
        PayloadLen = PRISMPATH_APP_PAYLOAD_LEN;
    }
    CFE_ES_PerfLogEntry(PRISMPATH_APP_DECIDE_PERF_ID);
    PP_AppDist_Propose(DIST, &PP_Io, Payload, PayloadLen, &Command, PRISMPATH_APP_MonitorAge(), PP_Now(), &Decision);
    CFE_ES_PerfLogExit(PRISMPATH_APP_DECIDE_PERF_ID);
    PRISMPATH_APP_Report();

    if (Decision.Escalated)
    {
        char hex[65];
        int  i;
        for (i = 0; i < 32; i++)
        {
            snprintf(&hex[2 * i], 3, "%02x", Decision.EscalationReceipt[i]);
        }
        /* OP3: the receipt hash the ground seals an operator's answer to, beside the PEP id of the state record */
        CFE_EVS_SendEvent(PRISMPATH_APP_ESCALATION_EID, CFE_EVS_EventType_CRITICAL,
                          "PRISMPATH_APP ESCALATION seq=%u receipt=%s", (unsigned int)Seq, hex);
    }
    if (Decision.NotEnacted)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.NotEnacted++;
        PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
        CFE_EVS_SendEvent(PRISMPATH_APP_NOT_ENACTED_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP NOT ENACTED seq=%u basis=floor cause=%u: an escalation past the floor's "
                          "rate has no line in a core run, so the request is refused unreceipted", (unsigned int)Seq,
                          (unsigned int)Decision.Cause);
        return;
    }
    if (Decision.RecordError)
    {
        PRISMPATH_APP_Data.HkTlm.Payload.RecordErrors++;
        CFE_EVS_SendEvent(PRISMPATH_APP_RECORD_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP RECORD ERROR seq=%u: the decision could not be receipted and is not acted on",
                          (unsigned int)Seq);
        if (Decision.Kind == PP_KIND_ALLOW)
        {
            PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
            return; /* an allow nobody can audit is not carried out */
        }
    }
    if (Decision.Receipted)
    {
        snprintf(Rcpt, sizeof(Rcpt), "%u%s", (unsigned int)Decision.Receipt, Decision.Held ? " held" : "");
    }
    else
    {
        if (!Decision.RecordError)
        {
            PRISMPATH_APP_Data.HkTlm.Payload.Unreceipted++;
        }
        snprintf(Rcpt, sizeof(Rcpt), "none");
    }

    switch (Decision.Kind)
    {
        case PP_KIND_ALLOW:
            PRISMPATH_APP_Data.HkTlm.Payload.Allowed++;
            CFE_EVS_SendEvent(PRISMPATH_APP_ALLOW_EID, CFE_EVS_EventType_INFORMATION,
                              "PRISMPATH_APP ALLOW seq=%u rule=%d receipt=%s monitor_ok=%u", (unsigned int)Seq,
                              (int)Decision.Rule, Rcpt, (unsigned int)Proposed.MonitorOk);
            PRISMPATH_APP_Forward(&Proposed, Seq);
            break;
        case PP_KIND_ESCALATE:
            PRISMPATH_APP_Data.HkTlm.Payload.Escalated++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Decision.Cause;
            CFE_EVS_SendEvent(PRISMPATH_APP_ESCALATE_EID, CFE_EVS_EventType_CRITICAL,
                              "PRISMPATH_APP ESCALATE seq=%u rule=%d cause=%u receipt=%s monitor_ok=%u",
                              (unsigned int)Seq, (int)Decision.Rule, (unsigned int)Decision.Cause, Rcpt,
                              (unsigned int)Proposed.MonitorOk);
            break;
        default:
            PRISMPATH_APP_Data.HkTlm.Payload.Refused++;
            PRISMPATH_APP_Data.HkTlm.Payload.LastRefusalCause = Decision.Cause;
            if (Decision.Rule >= 0)
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u rule=%d cause=%u receipt=%s", (unsigned int)Seq,
                                  (int)Decision.Rule, (unsigned int)Decision.Cause, Rcpt);
            }
            else
            {
                CFE_EVS_SendEvent(PRISMPATH_APP_REFUSE_EID, CFE_EVS_EventType_ERROR,
                                  "PRISMPATH_APP REFUSE seq=%u core cause=%u field=%s receipt=%s", (unsigned int)Seq,
                                  (unsigned int)Decision.Cause, PP_Kernel_FieldName(Decision.Field), Rcpt);
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
    Hk->ReceiptCount     = (uint32)PP_Run_Root(&DIST->Record.Run, Root);
    Hk->PolicyVersion    = PP_Kernel_Active() ? DIST->Active.Version : 0u;
    Hk->Seals            = (uint32)DIST->Record.Run.Seals;
    memcpy(Hk->Root, Root, sizeof(Hk->Root));
    CFE_SB_TimeStampMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader));
    CFE_SB_TransmitMsg(CFE_MSG_PTR(PRISMPATH_APP_Data.HkTlm.TelemetryHeader), true);
}

/* the housekeeping request: a beat record in the packet, and the counters in an event */
static void PRISMPATH_APP_Housekeeping(void)
{
    PRISMPATH_APP_HkTlm_Payload_t *Hk = &PRISMPATH_APP_Data.HkTlm.Payload;

    PP_AppDist_Beat(DIST, PP_Now());
    if (DIST->Step.N > 0)
    {
        memcpy(Hk->StateRecord, DIST->Step.Record[DIST->Step.N - 1], DIST->Step.Len[DIST->Step.N - 1]);
        Hk->StateRecordLen = (uint16)DIST->Step.Len[DIST->Step.N - 1];
    }
    PRISMPATH_APP_SendHk();
    CFE_EVS_SendEvent(PRISMPATH_APP_HK_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP HK proposed=%u allowed=%u refused=%u escalated=%u forwarded=%u active=%u "
                      "receipts=%u version=v%u floor=%u",
                      (unsigned int)Hk->Proposed, (unsigned int)Hk->Allowed, (unsigned int)Hk->Refused,
                      (unsigned int)Hk->Escalated, (unsigned int)Hk->Forwarded, (unsigned int)Hk->PolicyActive,
                      (unsigned int)Hk->ReceiptCount, (unsigned int)Hk->PolicyVersion,
                      (unsigned int)DIST->Pep.d.floor_seq);
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
    rc     = PP_Run_Seal(&DIST->Record.Run, &PP_Io, &DIST->Keys, TimeUs);
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
    (void)PP_AppDist_SaveRun(DIST);
    PRISMPATH_APP_Data.HkTlm.Payload.CommandCounter++;
    Leaves = (uint32)PP_Run_Root(&DIST->Record.Run, Root);
    for (i = 0; i < 32; i++)
    {
        snprintf(&Hex[2 * i], 3, "%02x", Root[i]);
    }
    CFE_EVS_SendEvent(PRISMPATH_APP_SEALED_EID, CFE_EVS_EventType_INFORMATION, "PRISMPATH_APP SEALED receipts=%u root=%s",
                      (unsigned int)Leaves, Leaves ? Hex : "-");
}

static void PRISMPATH_APP_DistCommand(const CFE_SB_Buffer_t *SBBufPtr, CFE_MSG_FcnCode_t Cc)
{
    if (Cc == PRISMPATH_APP_CONTROL_CC)
    {
        const PRISMPATH_APP_ControlCmd_t *Cmd = (const PRISMPATH_APP_ControlCmd_t *)SBBufPtr;
        if (!PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(*Cmd)) || Cmd->FrameLen > PRISMPATH_APP_FRAME_MAX)
        {
            return;
        }
        PP_AppDist_Control(DIST, Cmd->Frame, Cmd->FrameLen, Cmd->ImageSig, PP_NowMs(), PP_Now());
    }
    else
    {
        const PRISMPATH_APP_FrameCmd_t *Cmd = (const PRISMPATH_APP_FrameCmd_t *)SBBufPtr;
        if (!PRISMPATH_APP_VerifyLength(&SBBufPtr->Msg, sizeof(*Cmd)) || Cmd->FrameLen > PRISMPATH_APP_FRAME_MAX)
        {
            return;
        }
        PP_AppDist_Frame(DIST, Cmd->Frame, Cmd->FrameLen, PP_NowMs(), PP_Now());
    }
    PRISMPATH_APP_Data.HkTlm.Payload.CommandCounter++;
    PRISMPATH_APP_Report();
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
        case PRISMPATH_APP_OFFER_CC:
        case PRISMPATH_APP_CHUNK_CC:
        case PRISMPATH_APP_CONTROL_CC:
            PRISMPATH_APP_DistCommand(SBBufPtr, Cc);
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
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.MonitorMid))
    {
        PRISMPATH_APP_MonitorVerdict(SBBufPtr);
    }
    else if (CFE_SB_MsgId_Equal(MsgId, PRISMPATH_APP_Data.SendHkMid))
    {
        PRISMPATH_APP_Housekeeping();
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

        /* the table service's housekeeping, and the expiry check and a delayed commit at least once a poll (X1) */
        PRISMPATH_APP_ManageTable();
        PP_AppDist_Tick(DIST, PP_NowMs(), PP_Now());
        PRISMPATH_APP_Report();

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
    PRISMPATH_APP_Data.MonitorMid  = CFE_SB_ValueToMsgId(PRISMPATH_APP_MONITOR_VERDICT_MID);

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
#if PRISMPATH_APP_MONITOR_STALE_SECS > 0
    if (PRISMPATH_APP_Subscribe(PRISMPATH_APP_Data.MonitorMid) != CFE_SUCCESS)
    {
        return CFE_SB_BAD_ARGUMENT;
    }
#endif

    /* the table first: the enforcement point's start may switch to a boot release through it */
    Status = CFE_TBL_Register(&PRISMPATH_APP_Data.TblHandle, "PolicyTable", sizeof(PRISMPATH_APP_PolicyTable_t),
                              CFE_TBL_OPT_DEFAULT, PRISMPATH_APP_TblValidationFunc);
    if (Status != CFE_SUCCESS)
    {
        CFE_EVS_SendEvent(PRISMPATH_APP_TABLE_REG_ERR_EID, CFE_EVS_EventType_ERROR,
                          "PRISMPATH_APP error registering the policy table, RC = 0x%08lX", (unsigned long)Status);
        return Status;
    }
    PRISMPATH_APP_InitState();
    (void)PP_AppDist_LoadActive(DIST); /* after a reset the table service shows the table that decides */

    CFE_EVS_SendEvent(PRISMPATH_APP_INIT_INF_EID, CFE_EVS_EventType_INFORMATION,
                      "PRISMPATH_APP initialized, policy %s, %s reset, receipts=%u", PP_Kernel_Active() ? "active" : "NOT active",
                      CFE_ES_GetResetType(NULL) == CFE_PSP_RST_TYPE_PROCESSOR ? "processor" : "power on",
                      (unsigned int)DIST->Record.Run.Acc.count);
    return CFE_SUCCESS;
}
