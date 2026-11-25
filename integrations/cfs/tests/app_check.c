/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* Host check of the cFS app itself, prismpath_app.c, compiled with its enforcement point, kernel and run and the C core
 * of distribution against a stub of the cFE and OSAL calls it makes (stub_cfe/cfe.h), so what the app puts on the
 * software bus is seen. The files the app reads and writes under /cf are under ROOT, the Critical Data Store is memory,
 * and the table service runs the app's validation as CFE_TBL_Load does.
 *
 *   app_check ROOT < script
 *
 * Every message the app sends on the vehicle message id prints "sent <message id hex> <function code> <size> <the
 * bytes after the command header, hex>", and every event "event <id> <text>". The script's lines, the same as
 * dist_check.c takes for what both do:
 *
 *   authority <public hex> | instance <seed hex> | anchor <document hex> | bring <statement file hex>
 *                            the files the app's init reads; stale <seconds> must be the build's
 *   start <expiry> <lost floor> <min seq> <now>   the app's init at Unix time now; prints "init <status> <started>"
 *   frame <hex> <now ms> <now>                    an offer or chunk frame, as a ground command
 *   control <frame hex> <image sig hex> <now ms> <now>
 *   propose <payload hex> <monitor ok 0|1> <monitor age or -> <now> [<function code> [<size> [<message id hex>]]]
 *                            a proposal through the app's own handler, with the header's function code (0 unless
 *                            given), size (8 and the payload's unless given) and message id (the proposals' unless
 *                            given); a monitor verdict ok, when the monitor is ok, arrives first
 *   hk                       prints "hk <proposed> <allowed> <refused> <escalated> <forwarded> <not enacted>
 *                            <record errors>"
 *   seal <time us>           the app's seal command at that spacecraft time
 *   done
 */
#define _XOPEN_SOURCE 700 /* mkdir, open */
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cfe.h"

static const char *Root;
static long long   NowUnix;
static uint32      NowMs;
static uint64      SealUs;

/* ----------------------------------------------------------------- the software bus */
static uint16 Get16(const uint8 *b)
{
    return (uint16)(b[0] << 8 | b[1]);
}

CFE_SB_MsgId_t CFE_SB_ValueToMsgId(CFE_SB_MsgId_Atom_t Value)
{
    return Value;
}

CFE_SB_MsgId_Atom_t CFE_SB_MsgIdToValue(CFE_SB_MsgId_t MsgId)
{
    return MsgId;
}

bool CFE_SB_MsgId_Equal(CFE_SB_MsgId_t A, CFE_SB_MsgId_t B)
{
    return A == B;
}

CFE_Status_t CFE_MSG_SetMsgId(CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t MsgId)
{
    Msg->Byte[0] = (uint8)(MsgId >> 8);
    Msg->Byte[1] = (uint8)MsgId;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_Init(CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t MsgId, CFE_MSG_Size_t Size)
{
    memset(Msg, 0, Size < sizeof(CFE_MSG_CommandHeader_t) ? Size : sizeof(CFE_MSG_CommandHeader_t));
    (void)CFE_MSG_SetMsgId(Msg, MsgId);
    Msg->Byte[4] = (uint8)((Size - 7u) >> 8);
    Msg->Byte[5] = (uint8)(Size - 7u);
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GetSize(const CFE_MSG_Message_t *Msg, CFE_MSG_Size_t *Size)
{
    *Size = (CFE_MSG_Size_t)Get16(&Msg->Byte[4]) + 7u;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GetMsgId(const CFE_MSG_Message_t *Msg, CFE_SB_MsgId_t *MsgId)
{
    *MsgId = Get16(Msg->Byte);
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GetFcnCode(const CFE_MSG_Message_t *Msg, CFE_MSG_FcnCode_t *Fc)
{
    *Fc = ((const CFE_MSG_CommandHeader_t *)Msg)->Sec[0] & 0x7Fu;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_SetFcnCode(CFE_MSG_Message_t *Msg, CFE_MSG_FcnCode_t Fc)
{
    ((CFE_MSG_CommandHeader_t *)Msg)->Sec[0] = Fc & 0x7Fu;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_MSG_GenerateChecksum(CFE_MSG_Message_t *Msg)
{
    (void)Msg;
    return CFE_SUCCESS;
}

static CFE_SB_MsgId_t Vehicle; /* the vehicle message id the app sends on, set after its init */

CFE_Status_t CFE_SB_TransmitMsg(const CFE_MSG_Message_t *Msg, bool IncrementSequence)
{
    CFE_SB_MsgId_t    id = 0;
    CFE_MSG_Size_t    size = 0;
    CFE_MSG_FcnCode_t fc = 0;
    size_t            k;

    (void)IncrementSequence;
    (void)CFE_MSG_GetMsgId(Msg, &id);
    if (id != Vehicle)
    {
        return CFE_SUCCESS; /* housekeeping */
    }
    (void)CFE_MSG_GetSize(Msg, &size);
    (void)CFE_MSG_GetFcnCode(Msg, &fc);
    printf("sent %08x %u %u ", (unsigned)id, (unsigned)fc, (unsigned)size);
    for (k = sizeof(CFE_MSG_CommandHeader_t); k < size; k++)
    {
        printf("%02x", ((const uint8 *)Msg)[k]);
    }
    printf("%s\n", size > sizeof(CFE_MSG_CommandHeader_t) ? "" : "-");
    return CFE_SUCCESS;
}

void CFE_SB_TimeStampMsg(CFE_MSG_Message_t *Msg)
{
    (void)Msg;
}

CFE_Status_t CFE_SB_CreatePipe(CFE_SB_PipeId_t *Pipe, uint16 Depth, const char *Name)
{
    (void)Depth;
    (void)Name;
    *Pipe = 1;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_SB_SubscribeEx(CFE_SB_MsgId_t MsgId, CFE_SB_PipeId_t Pipe, int Qos, uint16 Limit)
{
    (void)MsgId;
    (void)Pipe;
    (void)Qos;
    (void)Limit;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_SB_ReceiveBuffer(CFE_SB_Buffer_t **Buf, CFE_SB_PipeId_t Pipe, int32 TimeOut)
{
    (void)Buf;
    (void)Pipe;
    (void)TimeOut;
    return CFE_SB_TIME_OUT;
}

/* ----------------------------------------------------------------- events, executive services, time */
CFE_Status_t CFE_EVS_Register(const void *Filters, uint16 N, uint16 Scheme)
{
    (void)Filters;
    (void)N;
    (void)Scheme;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_EVS_SendEvent(uint16 EventID, uint16 EventType, const char *Spec, ...)
{
    va_list ap;

    (void)EventType;
    printf("event %u ", (unsigned)EventID);
    va_start(ap, Spec);
    vprintf(Spec, ap);
    va_end(ap);
    printf("\n");
    return CFE_SUCCESS;
}

void CFE_ES_WriteToSysLog(const char *Spec, ...)
{
    (void)Spec;
}

/* the two Critical Data Store areas, by name, which the app registers once each */
static struct
{
    char   Name[32];
    size_t Size;
    uint8 *Data;
    int    Written;
} Cds[2];

CFE_Status_t CFE_ES_RegisterCDS(CFE_ES_CDSHandle_t *Handle, size_t Size, const char *Name)
{
    uint32 k;

    for (k = 0; k < 2; k++)
    {
        if (Cds[k].Data != NULL && strcmp(Cds[k].Name, Name) == 0)
        {
            *Handle = k;
            return Cds[k].Written ? CFE_ES_CDS_ALREADY_EXISTS : CFE_SUCCESS;
        }
        if (Cds[k].Data == NULL)
        {
            snprintf(Cds[k].Name, sizeof(Cds[k].Name), "%s", Name);
            Cds[k].Size = Size;
            Cds[k].Data = calloc(1, Size);
            *Handle     = k;
            return Cds[k].Data ? CFE_SUCCESS : -1;
        }
    }
    return -1;
}

CFE_Status_t CFE_ES_CopyToCDS(CFE_ES_CDSHandle_t Handle, const void *Data)
{
    memcpy(Cds[Handle].Data, Data, Cds[Handle].Size);
    Cds[Handle].Written = 1;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_ES_RestoreFromCDS(void *Data, CFE_ES_CDSHandle_t Handle)
{
    memcpy(Data, Cds[Handle].Data, Cds[Handle].Size);
    return CFE_SUCCESS;
}

int32 CFE_ES_GetResetType(uint32 *Subtype)
{
    (void)Subtype;
    return CFE_PSP_RST_TYPE_POWERON;
}

bool CFE_ES_RunLoop(uint32 *RunStatus)
{
    (void)RunStatus;
    return false;
}

void CFE_ES_ExitApp(uint32 ExitStatus)
{
    (void)ExitStatus;
}

void CFE_ES_PerfLogEntry(uint32 Id)
{
    (void)Id;
}

void CFE_ES_PerfLogExit(uint32 Id)
{
    (void)Id;
}

CFE_TIME_SysTime_t CFE_TIME_GetMET(void)
{
    CFE_TIME_SysTime_t t = {NowMs / 1000u, (NowMs % 1000u) * 1000u};
    return t;
}

CFE_TIME_SysTime_t CFE_TIME_GetUTC(void)
{
    CFE_TIME_SysTime_t t = {(uint32)(NowUnix - 315532800LL), 0};
    return t;
}

CFE_TIME_SysTime_t CFE_TIME_GetTime(void)
{
    CFE_TIME_SysTime_t t = {(uint32)(SealUs / 1000000u), (uint32)(SealUs % 1000000u)};
    return t;
}

uint32 CFE_TIME_GetMETseconds(void)
{
    return NowMs / 1000u;
}

uint32 CFE_TIME_Sub2MicroSecs(uint32 Subseconds)
{
    return Subseconds; /* this stub's subseconds are microseconds */
}

/* ----------------------------------------------------------------- the table service */
static CFE_TBL_CallbackFuncPtr_t Validate;
static uint8                     Table[65536];

CFE_Status_t CFE_TBL_Register(CFE_TBL_Handle_t *Handle, const char *Name, size_t Size, uint16 Options,
                              CFE_TBL_CallbackFuncPtr_t Fn)
{
    (void)Name;
    (void)Options;
    if (Size > sizeof(Table))
    {
        return -1;
    }
    *Handle  = 1;
    Validate = Fn;
    return CFE_SUCCESS;
}

CFE_Status_t CFE_TBL_Load(CFE_TBL_Handle_t Handle, int SrcType, const void *Src);
CFE_Status_t CFE_TBL_Manage(CFE_TBL_Handle_t Handle)
{
    (void)Handle;
    return CFE_SUCCESS;
}

/* ----------------------------------------------------------------- OSAL files, under ROOT */
static void Under(const char *Path, char *Out, size_t Cap)
{
    snprintf(Out, Cap, "%s%s", Root, Path);
}

int32 OS_OpenCreate(osal_id_t *Fd, const char *Path, int32 Flags, int32 Access)
{
    char path[1024];
    int  mode = Access == OS_WRITE_ONLY ? O_WRONLY : O_RDONLY;

    Under(Path, path, sizeof(path));
    if (Flags & OS_FILE_FLAG_CREATE)
    {
        mode |= O_CREAT;
    }
    if (Flags & OS_FILE_FLAG_TRUNCATE)
    {
        mode |= O_TRUNC;
    }
    *Fd = open(path, mode, 0644);
    return *Fd >= 0 ? OS_SUCCESS : -1;
}

int32 OS_close(osal_id_t Fd)
{
    return close(Fd) == 0 ? OS_SUCCESS : -1;
}

int32 OS_read(osal_id_t Fd, void *Buf, size_t Len)
{
    return (int32)read(Fd, Buf, Len);
}

int32 OS_write(osal_id_t Fd, const void *Buf, size_t Len)
{
    return (int32)write(Fd, Buf, Len);
}

int32 OS_lseek(osal_id_t Fd, int32 Offset, uint32 Whence)
{
    return (int32)lseek(Fd, Offset, Whence == OS_SEEK_END ? SEEK_END : SEEK_SET);
}

int32 OS_stat(const char *Path, os_fstat_t *St)
{
    char        path[1024];
    struct stat st;

    Under(Path, path, sizeof(path));
    if (stat(path, &st) != 0)
    {
        return -1;
    }
    St->FileSize = (size_t)st.st_size;
    return OS_SUCCESS;
}

int32 OS_rename(const char *Old, const char *New)
{
    char a[1024], b[1024];

    Under(Old, a, sizeof(a));
    Under(New, b, sizeof(b));
    return rename(a, b) == 0 ? OS_SUCCESS : -1;
}

int32 OS_mkdir(const char *Path, uint32 Access)
{
    char path[1024];

    (void)Access;
    Under(Path, path, sizeof(path));
    return mkdir(path, 0755) == 0 ? OS_SUCCESS : -1;
}

/* ----------------------------------------------------------------- the app */
#include "prismpath_app_kernel.c"
#include "prismpath_app_run.c"
#include "prismpath_app_dist.c"
#include "prismpath_app.c"

CFE_Status_t CFE_TBL_Load(CFE_TBL_Handle_t Handle, int SrcType, const void *Src)
{
    (void)Handle;
    (void)SrcType;
    memcpy(Table, Src, sizeof(PRISMPATH_APP_PolicyTable_t));
    return Validate != NULL && Validate(Table) == CFE_SUCCESS ? CFE_SUCCESS : -1;
}

static size_t Unhex(const char *Hex, uint8 *Out, size_t Cap)
{
    size_t n = 0;
    while (Hex[0] && Hex[1] && n < Cap)
    {
        unsigned v;
        if (sscanf(Hex, "%2x", &v) != 1)
        {
            break;
        }
        Out[n++] = (uint8)v;
        Hex += 2;
    }
    return n;
}

static void PutFile(const char *Path, const uint8 *Data, size_t Len)
{
    char  path[1024];
    FILE *f;

    Under(Path, path, sizeof(path));
    f = fopen(path, "wb");
    if (f == NULL || fwrite(Data, 1, Len, f) != Len)
    {
        fprintf(stderr, "app_check: cannot write %s\n", path);
        exit(2);
    }
    fclose(f);
}

static void Command(void *Cmd, size_t Size, CFE_SB_MsgId_t Mid, CFE_MSG_FcnCode_t Fc)
{
    CFE_MSG_Init((CFE_MSG_Message_t *)Cmd, Mid, Size);
    (void)CFE_MSG_SetFcnCode((CFE_MSG_Message_t *)Cmd, Fc);
    PRISMPATH_APP_TaskPipe((const CFE_SB_Buffer_t *)Cmd);
}

int main(int argc, char **argv)
{
    static char  line[2 * (PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 200)];
    static char  a[sizeof(line)], b[sizeof(line)];
    static uint8 bytes[sizeof(line) / 2];
    unsigned     brought = 0;
    char         path[1024];

    if (argc != 2)
    {
        printf("usage: app_check ROOT < script\n");
        return 2;
    }
    Root = argv[1];
    Under("/cf", path, sizeof(path));
    (void)mkdir(path, 0755);
    while (fgets(line, sizeof(line), stdin))
    {
        char      word[32];
        int       skip = 0;
        unsigned  now_ms = 0;
        line[strcspn(line, "\n")] = 0;
        if (sscanf(line, "%31s %n", word, &skip) < 1)
        {
            continue;
        }
        const char *rest = line + skip;
        if (strcmp(word, "done") == 0)
        {
            return 0;
        }
        if (strcmp(word, "authority") == 0 || strcmp(word, "instance") == 0 || strcmp(word, "anchor") == 0)
        {
            size_t n = Unhex(rest, bytes, sizeof(bytes));
            PutFile(word[0] == 'a' && word[1] == 'u' ? PRISMPATH_APP_PLATFORM_AUTHORITY_FILE
                : word[0] == 'i'                 ? PRISMPATH_APP_PLATFORM_INSTANCE_FILE
                                                 : PRISMPATH_APP_PLATFORM_ANCHOR_FILE,
                bytes, n);
        }
        else if (strcmp(word, "bring") == 0)
        {
            char name[OS_MAX_PATH_LEN];
            size_t n = Unhex(rest, bytes, sizeof(bytes));
            snprintf(name, sizeof(name), PRISMPATH_APP_PLATFORM_BRING_FILE, brought++);
            PutFile(name, bytes, n);
        }
        else if (strcmp(word, "stale") == 0)
        {
            if (strtoul(rest, NULL, 10) != PRISMPATH_APP_MONITOR_STALE_SECS)
            {
                fprintf(stderr, "app_check: built with a staleness bound of %u\n", PRISMPATH_APP_MONITOR_STALE_SECS);
                return 2;
            }
        }
        else if (strcmp(word, "start") == 0)
        {
            int       e, l;
            long long m;
            if (sscanf(rest, "%d %d %lld %lld", &e, &l, &m, &NowUnix) != 4)
            {
                return 2;
            }
            CFE_Status_t rc = PRISMPATH_APP_Init();
            Vehicle         = PRISMPATH_APP_Data.VehicleMid;
            printf("init %d %d\n", (int)rc, (int)PRISMPATH_APP_Data.DistStarted);
        }
        else if (strcmp(word, "frame") == 0 || strcmp(word, "control") == 0)
        {
            PRISMPATH_APP_ControlCmd_t cmd;
            memset(&cmd, 0, sizeof(cmd));
            if (word[0] == 'f')
            {
                PRISMPATH_APP_FrameCmd_t *f = (PRISMPATH_APP_FrameCmd_t *)&cmd;
                if (sscanf(rest, "%s %u %lld", a, &now_ms, &NowUnix) != 3)
                {
                    return 2;
                }
                NowMs       = now_ms;
                f->FrameLen = (uint16)Unhex(a, f->Frame, sizeof(f->Frame));
                Command(f, sizeof(*f), PRISMPATH_APP_Data.CmdMid, PRISMPATH_APP_CHUNK_CC);
            }
            else
            {
                if (sscanf(rest, "%s %s %u %lld", a, b, &now_ms, &NowUnix) != 4)
                {
                    return 2;
                }
                NowMs        = now_ms;
                cmd.FrameLen = (uint16)Unhex(a, cmd.Frame, sizeof(cmd.Frame));
                Unhex(b, cmd.ImageSig, sizeof(cmd.ImageSig));
                Command(&cmd, sizeof(cmd), PRISMPATH_APP_Data.CmdMid, PRISMPATH_APP_CONTROL_CC);
            }
        }
        else if (strcmp(word, "propose") == 0)
        {
            static CFE_SB_Buffer_t buf;
            int                    ok = 1;
            unsigned               fc = 0, size = 0, mid = 0;
            size_t                 n;
            if (sscanf(rest, "%s %d %s %lld %u %u %x", a, &ok, b, &NowUnix, &fc, &size, &mid) < 4 || fc > 127)
            {
                return 2;
            }
            if (ok)
            {
                PRISMPATH_APP_MonitorVerdict_t v;
                memset(&v, 0, sizeof(v));
                v.Ok = 1;
                Command(&v, sizeof(v), PRISMPATH_APP_Data.MonitorMid, 0);
            }
            memset(&buf, 0, sizeof(buf));
            n = Unhex(a, &buf.Bytes[sizeof(CFE_MSG_CommandHeader_t)], sizeof(buf.Bytes) - sizeof(CFE_MSG_CommandHeader_t));
            CFE_MSG_Init(&buf.Msg, mid ? mid : CFE_SB_MsgIdToValue(PRISMPATH_APP_Data.ProposedMid),
                         size ? size : sizeof(CFE_MSG_CommandHeader_t) + n);
            (void)CFE_MSG_SetFcnCode(&buf.Msg, (CFE_MSG_FcnCode_t)fc);
            PRISMPATH_APP_Proposal(&buf); /* its own handler, so a proposal on another id reaches it too */
        }
        else if (strcmp(word, "hk") == 0)
        {
            const PRISMPATH_APP_HkTlm_Payload_t *h = &PRISMPATH_APP_Data.HkTlm.Payload;
            printf("hk %u %u %u %u %u %u %u\n", (unsigned)h->Proposed, (unsigned)h->Allowed, (unsigned)h->Refused,
                   (unsigned)h->Escalated, (unsigned)h->Forwarded, (unsigned)h->NotEnacted,
                   (unsigned)h->RecordErrors);
        }
        else if (strcmp(word, "seal") == 0)
        {
            PRISMPATH_APP_SealCmd_t cmd;
            SealUs = strtoull(rest, NULL, 10);
            Command(&cmd, sizeof(cmd), PRISMPATH_APP_Data.CmdMid, PRISMPATH_APP_SEAL_CC);
        }
        else
        {
            fprintf(stderr, "app_check: unknown line %s\n", word);
            return 2;
        }
        fflush(stdout);
    }
    return 0;
}
