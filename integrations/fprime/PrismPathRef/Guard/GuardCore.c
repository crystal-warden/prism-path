/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

#define _POSIX_C_SOURCE 200809L /* truncate, mkdir */
#include "GuardCore.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "prismpath_app_kernel.h"
#include "prismpath_app_layout.h"
#include "prismpath_app_run.h"

#define GC_HANDLES 4
#define GC_FILE_HEADERS 116 /* a cFE table file: 64 byte file header and 52 byte table header */

struct GC
{
    PP_RunState_t    Run;
    PP_RunKeys_t     Keys;
    PP_RunIo_t       Io;
    PP_PolicyTable_t Active;
    uint8_t          ActiveDigest[32];
    int              Begun;
    char             Dir[160];
    FILE            *Handles[GC_HANDLES];
};

/* ----------------------------------------------------------------- the run's files, through stdio */
static int32_t IoOpen(void *Ctx, int File, int Mode)
{
    GC     *Core = (GC *)Ctx;
    char    Path[256];
    int32_t H;

    for (H = 0; H < GC_HANDLES && Core->Handles[H] != NULL; H++)
    {
    }
    if (H == GC_HANDLES)
    {
        return -1;
    }
    snprintf(Path, sizeof(Path), "%s/%s", Core->Dir, PP_RunFileNames[File]);
    Core->Handles[H] = fopen(Path, Mode == PP_IO_READ ? "rb" : Mode == PP_IO_APPEND ? "ab" : "wb");
    return Core->Handles[H] != NULL ? H : -1;
}

static int32_t IoWrite(void *Ctx, int32_t H, const void *Buf, size_t Len)
{
    FILE *F = ((GC *)Ctx)->Handles[H];

    return (fwrite(Buf, 1, Len, F) == Len && fflush(F) == 0) ? 0 : -1;
}

static int32_t IoRead(void *Ctx, int32_t H, void *Buf, size_t Len)
{
    return (int32_t)fread(Buf, 1, Len, ((GC *)Ctx)->Handles[H]);
}

static void IoClose(void *Ctx, int32_t H)
{
    GC *Core = (GC *)Ctx;

    fclose(Core->Handles[H]);
    Core->Handles[H] = NULL;
}

static int64_t IoSize(void *Ctx, int File)
{
    GC         *Core = (GC *)Ctx;
    char        Path[256];
    struct stat St;

    snprintf(Path, sizeof(Path), "%s/%s", Core->Dir, PP_RunFileNames[File]);
    return stat(Path, &St) == 0 ? (int64_t)St.st_size : -1;
}

static int32_t IoTruncate(void *Ctx, int File, uint64_t Len)
{
    GC  *Core = (GC *)Ctx;
    char Path[256];

    snprintf(Path, sizeof(Path), "%s/%s", Core->Dir, PP_RunFileNames[File]);
    return truncate(Path, (off_t)Len) == 0 ? 0 : -1;
}

GC *GC_Create(void)
{
    GC *Core = (GC *)calloc(1, sizeof(GC));

    if (Core != NULL)
    {
        Core->Io.Ctx      = Core;
        Core->Io.Open     = IoOpen;
        Core->Io.Write    = IoWrite;
        Core->Io.Read     = IoRead;
        Core->Io.Close    = IoClose;
        Core->Io.Size     = IoSize;
        Core->Io.Truncate = IoTruncate;
        PP_Run_Init(&Core->Run);
    }
    return Core;
}

void GC_Destroy(GC *Core)
{
    free(Core);
}

/* ----------------------------------------------------------------- keys and the table */
static int ReadFixed(const char *Dir, const char *Name, void *Out, size_t Len)
{
    char   Path[320];
    FILE  *F;
    size_t N;

    snprintf(Path, sizeof(Path), "%s/%s", Dir, Name);
    F = fopen(Path, "rb");
    if (F == NULL)
    {
        return 0;
    }
    N = fread(Out, 1, Len, F);
    fclose(F);
    return N == Len;
}

/* The table file's bytes into Out, the struct alone or after a cFE file's headers. 0 when unreadable. */
static int ReadTable(const char *Path, PP_PolicyTable_t *Out)
{
    FILE         *F = fopen(Path, "rb");
    unsigned char Head[GC_FILE_HEADERS];
    long          Size;

    if (F == NULL)
    {
        return 0;
    }
    fseek(F, 0, SEEK_END);
    Size = ftell(F);
    fseek(F, 0, SEEK_SET);
    if (Size == (long)(sizeof(*Out) + GC_FILE_HEADERS) && fread(Head, 1, sizeof(Head), F) != sizeof(Head))
    {
        Size = -1;
    }
    else if (Size != (long)sizeof(*Out) && Size != (long)(sizeof(*Out) + GC_FILE_HEADERS))
    {
        Size = -1;
    }
    if (Size < 0 || fread(Out, 1, sizeof(*Out), F) != sizeof(*Out))
    {
        fclose(F);
        return 0;
    }
    fclose(F);
    return 1;
}

int GC_Load(GC *Core, const char *PolicyFile, const char *KeysDir, const char *RunDir, uint32_t *Version,
            uint32_t *Rules, char What[64])
{
    static PP_PolicyTable_t Table; /* 5 KB, kept off the thread's stack */
    uint8_t                 Seed[32];
    uint8_t                 Digest[32];
    int                     rc;

    Core->Keys.HaveAuthority = ReadFixed(KeysDir, "pp_authority.pub", Core->Keys.AuthorityPub, 32);
    if (!Core->Keys.HaveAuthority)
    {
        snprintf(What, 64, "no authority key pp_authority.pub");
        return -1;
    }
    if (ReadFixed(KeysDir, "pp_instance.key", Seed, sizeof(Seed)))
    {
        PP_Run_SetInstanceSeed(&Core->Keys, Seed);
    }
    memset(Seed, 0, sizeof(Seed));
    if (!ReadTable(PolicyFile, &Table))
    {
        snprintf(What, 64, "policy table unreadable or not a table");
        return -1;
    }
    if (!Core->Begun)
    {
        snprintf(Core->Dir, sizeof(Core->Dir), "%s", RunDir);
        (void)mkdir(Core->Dir, 0777);
        if (PP_Run_Begin(&Core->Io) != 0)
        {
            snprintf(What, 64, "cannot create the run files");
            return -1;
        }
        Core->Begun = 1;
    }
    rc = PP_Kernel_Check(&Table);
    if (rc == 0)
    {
        rc = PP_Run_CheckSignedTable(&Core->Run, &Core->Keys, &Table, Digest);
    }
    if (rc == 0)
    {
        rc = PP_Kernel_Activate(&Table);
    }
    if (rc != 0)
    {
        return rc;
    }
    Core->Active = Table;
    memcpy(Core->ActiveDigest, Digest, sizeof(Digest));
    PP_Run_Accept(&Core->Run, Table.Version, Digest);
    *Version = Table.Version;
    *Rules   = Table.RuleCount;
    return 0;
}

/* ----------------------------------------------------------------- a proposal */
/* a MONITOR row is the runtime monitor's verdict, which an app supplies and no command carries ("MONITOR" is the
 * only kind name 8 bytes long once stringized) */
#define ROW(Reg, Name, Kind, Off, Width, Lo, Hi, Role) {Off, Width, sizeof(#Kind) == sizeof("MONITOR")},
static const struct
{
    uint8_t Off;
    uint8_t Width;
    uint8_t App;
} Layout[PRISMPATH_APP_FIELD_COUNT] = {PRISMPATH_APP_FIELDS(ROW)};
#undef ROW

/* F Prime serializes a command's arguments big endian, one after another in the order they are declared, which
 * is the layout's register order less the fields an app supplies (the monitor's verdict). The policy reads little endian at the layout's offsets (the cFS payload), so
 * each field the arguments hold completely is put at its offset, byte reversed. The payload ends where the last
 * complete field ends, so a packet cut short is the core's "missing" refusal, as a short cFS payload is. */
static size_t Adapt(const uint8_t *Args, size_t Len, uint8_t Out[PRISMPATH_APP_PAYLOAD_LEN])
{
    size_t Used = 0;
    size_t End  = 0;
    int    I;
    int    B;

    memset(Out, 0, PRISMPATH_APP_PAYLOAD_LEN);
    for (I = 0; I < PRISMPATH_APP_FIELD_COUNT; I++)
    {
        if (Layout[I].App)
        {
            continue;
        }
        if (Used + Layout[I].Width > Len)
        {
            break;
        }
        for (B = 0; B < Layout[I].Width; B++)
        {
            Out[Layout[I].Off + B] = Args[Used + Layout[I].Width - 1 - B];
        }
        Used += Layout[I].Width;
        End = (size_t)Layout[I].Off + Layout[I].Width;
    }
    return End;
}

int GC_Propose(GC *Core, const uint8_t *Args, size_t Len, GC_Outcome *Out)
{
    uint8_t      Payload[PRISMPATH_APP_PAYLOAD_LEN];
    size_t       PayloadLen = Adapt(Args, Len, Payload);
    PP_Verdict_t Verdict;
    uint64_t     Index = 0;

    memset(Out, 0, sizeof(*Out));
    Out->Receipt = -1;
    PP_Kernel_Decide(Payload, PayloadLen, &Verdict);
    Out->Kind  = Verdict.Kind;
    Out->Rule  = Verdict.Rule;
    Out->Cause = Verdict.Cause;
    if (Verdict.Rule < 0 && Verdict.Field >= 0)
    {
        snprintf(Out->Field, sizeof(Out->Field), "%s", PP_Kernel_FieldName(Verdict.Field));
    }
    /* the receipt comes before anything is acted on; with no image there is nothing to bind it to */
    if (PP_Kernel_Active())
    {
        if (PP_Run_Record(&Core->Run, &Core->Io, &Core->Keys, &Core->Active, Core->ActiveDigest, Payload, PayloadLen,
                          &Verdict, 0, &Index) == 0)
        {
            Out->Receipt = (int64_t)Index;
        }
        else if (Verdict.Kind == PP_KIND_ALLOW)
        {
            Out->Kind = GC_RECORD_ERROR; /* an allow nobody can audit is not carried out */
        }
    }
    return 0;
}

int GC_Seal(GC *Core, uint64_t TimeUs, uint32_t *Leaves, char Root[65])
{
    uint8_t Raw[32];
    int     rc = PP_Run_Seal(&Core->Run, &Core->Io, &Core->Keys, TimeUs);
    int     I;

    *Leaves = (uint32_t)PP_Run_Root(&Core->Run, Raw);
    for (I = 0; I < 32; I++)
    {
        snprintf(&Root[2 * I], 3, "%02x", Raw[I]);
    }
    return rc;
}

uint32_t GC_Receipts(const GC *Core)
{
    uint8_t Raw[32];

    return (uint32_t)PP_Run_Root(&Core->Run, Raw);
}

int GC_Active(const GC *Core)
{
    (void)Core;
    return PP_Kernel_Active();
}
