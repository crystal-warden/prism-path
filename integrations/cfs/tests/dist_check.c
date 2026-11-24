/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* Host check of the cFS app as an enforcement point of policy distribution (prismpath_app_dist.c) with its kernel,
 * its run and the C core of distribution, and no cFS in it. The Critical Data Store areas are two images in memory
 * that a processor reset keeps, the app's files are a directory, and the table service is a stub that runs the
 * app's validation as CFE_TBL_Load does, or refuses when told to.
 *
 *   dist_check RUN_DIR DIST_DIR < script
 *
 * The script's lines, each printing "records <hex of each state record the step made>" and then
 * "step <hold began> <hold ended> <provisioned> <locked> <floor at minimum> <table cause> <table busy> <dropped>
 * <answered> <answer allow>", and after a step that applied an operator's answer "answered <envelope id> <receipt>
 * <operator case written> <record error> <its receipt index> <the request it carries out, hex> <enact> <not enacted>
 * <message id hex> <function code> <size>", the command an answer `allow` sends, or "-" for each of the three:
 *
 *   authority <public hex> | instance <seed hex> | anchor <document hex> | stale <seconds>
 *   bring <statement file hex> | boot_release <statement file hex>     what the next start is provisioned with
 *   start <expiry 0|1> <lost floor 0 lock|1 minimum> <min seq> <now>   as the app's init: the stores as they are
 *   frame <hex> <now ms> <now> | control <frame hex> <image sig hex> <now ms> <now>
 *   tick <now ms> <now> | rollback <now> | beat <now>
 *   propose <payload hex> <monitor ok 0|1> <monitor age or -> <now> [<function code>]   proposed as command code 0,
 *                                                                      or the one given, on PROPOSED_MID; also prints "decision <kind> <cause> <rule>
 *                                                                      <basis> <held> <receipted> <receipt>
 *                                                                      <not enacted> <record error> <escalated>",
 *                                                                      and "escalation <receipt hash hex>" for an
 *                                                                      escalation of the action floor (OP3)
 *   reset                    a processor reset: memory is lost, the store images and the files are kept
 *   power                    a power on reset: the store images are lost, the files are kept
 *   lose record | lose copy  that store image no longer reads
 *   older                    the rates part in both copies written again as a build before an escalation kept its
 *                            command wrote it, the open escalations in the older layout
 *   unlink <file>            a file of DIST_DIR is gone
 *   tblfail <n>              the next n table loads are refused by the table service for its own reason
 *   groundload <table hex>   a table loaded by the ground from a file: prints "validation <cause>"
 *   seal <time us>           prints "sealed <rc>"
 *   state                    prints "state <has active> <active seq> <floor seq> <locked> <held> <kernel active>"
 *   held                     prints "held" and the envelope id of the held floor, fallback policy and ceiling, or "-"
 *   service                  prints "service <the version of the table the table service holds>"
 *   sizes                    prints "sizes <PP_AppDist_t> <pp_pep_machine> <record> <copy>"
 *   done
 */
#define _XOPEN_SOURCE 700 /* truncate */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "prismpath_app_kernel.c"
#include "prismpath_app_run.c"
#include "prismpath_app_dist.c"

/* ----------------------------------------------------------------- stdio files, as run_check.c has them */
static const char *RunDir, *DistDir;
static FILE       *Handles[8];

static int32_t IoOpen(void *Ctx, int File, int Mode)
{
    char    path[1024];
    int32_t h;

    (void)Ctx;
    for (h = 0; h < 8 && Handles[h] != NULL; h++)
    {
    }
    if (h == 8)
    {
        return -1;
    }
    snprintf(path, sizeof(path), "%s/%s", RunDir, PP_RunFileNames[File]);
    Handles[h] = fopen(path, Mode == PP_IO_READ ? "rb" : Mode == PP_IO_APPEND ? "ab" : "wb");
    return Handles[h] ? h : -1;
}

static int32_t IoWrite(void *Ctx, int32_t H, const void *Buf, size_t Len)
{
    (void)Ctx;
    return fwrite(Buf, 1, Len, Handles[H]) == Len ? 0 : -1;
}

static int32_t IoRead(void *Ctx, int32_t H, void *Buf, size_t Len)
{
    (void)Ctx;
    return (int32_t)fread(Buf, 1, Len, Handles[H]);
}

static void IoClose(void *Ctx, int32_t H)
{
    (void)Ctx;
    fclose(Handles[H]);
    Handles[H] = NULL;
}

static int64_t IoSize(void *Ctx, int File)
{
    char  path[1024];
    FILE *f;
    long  n;

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", RunDir, PP_RunFileNames[File]);
    f = fopen(path, "rb");
    if (f == NULL)
    {
        return -1;
    }
    fseek(f, 0, SEEK_END);
    n = ftell(f);
    fclose(f);
    return n;
}

static int32_t IoTruncate(void *Ctx, int File, uint64_t Len)
{
    char path[1024];

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", RunDir, PP_RunFileNames[File]);
    return truncate(path, (off_t)Len) == 0 ? 0 : -1;
}

static const PP_RunIo_t Io = {NULL, IoOpen, IoWrite, IoRead, IoClose, IoSize, IoTruncate};

/* ----------------------------------------------------------------- the stores */
static PP_AppDist_t        Dist;
static PP_AppRecord_t      SavedRecord; /* the Critical Data Store areas, which a processor reset keeps */
static PP_AppInstallCopy_t SavedCopy;
static int                 RecordState, CopyState; /* PP_APP_STORE_* each holds */
static int                 TableFails;

static int SaveRecord(void *Ctx)
{
    (void)Ctx;
    memcpy(&SavedRecord, &Dist.Record, sizeof(SavedRecord));
    RecordState = PP_APP_STORE_READ;
    return 0;
}

static int SaveCopy(void *Ctx)
{
    (void)Ctx;
    memcpy(&SavedCopy, &Dist.Copy, sizeof(SavedCopy));
    CopyState = PP_APP_STORE_READ;
    return 0;
}

static int WriteFile(void *Ctx, const char *Name, const void *Data, size_t Len)
{
    char  path[1024], temp[1100];
    FILE *f;

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", DistDir, Name);
    snprintf(temp, sizeof(temp), "%s.new", path);
    f = fopen(temp, "wb");
    if (f == NULL || fwrite(Data, 1, Len, f) != Len)
    {
        if (f)
        {
            fclose(f);
        }
        return -1;
    }
    fclose(f);
    return rename(temp, path) == 0 ? 0 : -1;
}

static int32_t ReadFile(void *Ctx, const char *Name, void *Data, size_t Cap)
{
    char   path[1024];
    FILE  *f;
    size_t n;

    (void)Ctx;
    snprintf(path, sizeof(path), "%s/%s", DistDir, Name);
    f = fopen(path, "rb");
    if (f == NULL)
    {
        return -1;
    }
    n = fread(Data, 1, Cap, f);
    fclose(f);
    return (int32_t)n;
}

/* CFE_TBL_Load from an address by the owner: its validation callback, then the table is the table service's */
static PP_PolicyTable_t TableService;
static int LoadTable(void *Ctx, const PP_PolicyTable_t *Table)
{
    (void)Ctx;
    if (TableFails > 0)
    {
        TableFails--;
        return -1;
    }
    if (PP_AppDist_ValidateTable(&Dist, Table) != 0)
    {
        return -1;
    }
    TableService = *Table;
    return 0;
}

/* ----------------------------------------------------------------- inputs */
static size_t Unhex(const char *Text, uint8_t *Out, size_t Room)
{
    size_t n = strlen(Text);
    size_t k;

    if (strcmp(Text, "-") == 0)
    {
        return 0;
    }
    if (n % 2 || n / 2 > Room)
    {
        fprintf(stderr, "dist_check: hex of %zu digits does not fit %zu bytes\n", n, Room);
        exit(2);
    }
    for (k = 0; k < n / 2; k++)
    {
        unsigned v;
        if (sscanf(Text + 2 * k, "%2x", &v) != 1)
        {
            exit(2);
        }
        Out[k] = (uint8_t)v;
    }
    return n / 2;
}

static void PrintStep(void)
{
    const PP_AppStep_t *s = &Dist.Step;
    size_t              k, j;

    printf("records");
    for (k = 0; k < s->N; k++)
    {
        printf(" ");
        for (j = 0; j < s->Len[k]; j++)
        {
            printf("%02x", s->Record[k][j]);
        }
    }
    printf("\nstep %d %d %d %d %d %u %d %u %d %d\n", s->HoldBegan, s->HoldEnded, s->Provisioned, s->Locked, s->FloorAt,
           (unsigned)s->TableCause, s->TableBusy, (unsigned)s->Dropped, s->Answered, s->AnswerAllow);
    if (s->Answered)
    {
        printf("answered ");
        for (j = 0; j < 32; j++)
        {
            printf("%02x", s->AnswerId[j]);
        }
        printf(" ");
        for (j = 0; j < 32; j++)
        {
            printf("%02x", s->AnswerReceipt[j]);
        }
        printf(" %d %d %llu ", s->AnswerReceipted, s->AnswerRecordError, (unsigned long long)s->AnswerIndex);
        for (j = 0; j < s->AnswerRequestLen; j++)
        {
            printf("%02x", s->AnswerRequest[j]);
        }
        printf("%s %d %d ", s->AnswerRequestLen ? "" : "-", s->AnswerEnact, s->AnswerNotEnacted);
        if (s->AnswerEnact)
        {
            printf("%08x %u %u\n", (unsigned)s->AnswerCommand.MsgId, (unsigned)s->AnswerCommand.FcnCode,
                   (unsigned)s->AnswerCommand.Size);
        }
        else
        {
            printf("- - -\n");
        }
    }
}

#define PROPOSED_MID 0x1882u /* the proposals' message id the script's commands are proposed on */

/* the size of an escalation in the layout before it kept its command: the members up to its cause, padded to the
 * escalation's alignment */
typedef struct
{
    char          c;
    pp_escalation e;
} Aligned_t;
#define OLDER_ESCALATION                                                                                               \
    ((offsetof(pp_escalation, command_len) + offsetof(Aligned_t, e) - 1) / offsetof(Aligned_t, e) *                    \
     offsetof(Aligned_t, e))

/* the rates part as an older build packs it: the same part with each open escalation cut to the older layout */
static void Older(void)
{
    static uint8_t now[PP_APP_RATES_BYTES], then[PP_APP_RATES_BYTES];
    size_t         n    = pp_durable_pack(&Dist.Pep.d, PP_PART_RATES, now, sizeof(now));
    size_t         open = Dist.Pep.d.n_open;
    size_t         head = n - open * sizeof(pp_escalation);
    size_t         k, len;

    memcpy(then, now, head);
    for (k = 0; k < open; k++)
    {
        memcpy(then + head + k * OLDER_ESCALATION, now + head + k * sizeof(pp_escalation), OLDER_ESCALATION);
    }
    len = head + open * OLDER_ESCALATION;
    memcpy(SavedCopy.Bytes + CopyAt(PP_APP_COPY_RATES), then, len);
    SavedCopy.Len[PP_APP_COPY_RATES] = (uint32_t)len;
    (void)WriteFile(NULL, PP_AppDistFiles[3 + PP_APP_COPY_RATES], then, len);
}

static PP_AppDistConfig_t Config;
static uint8_t            AnchorDoc[4096];
static uint8_t            Statements[PP_APP_BROUGHT_MAX + PP_APP_BOOT_MAX][8 + PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 80];
static size_t             NStatements;

int main(int argc, char **argv)
{
    static char line[2 * (PP_MAX_SEALED + PP_INSTALL_BODY_MAX + 200)];
    static char a[sizeof(line)], b[sizeof(line)];
    static uint8_t bytes[sizeof(line) / 2];
    static PP_PolicyTable_t ground;

    if (argc != 3)
    {
        printf("usage: dist_check RUN_DIR DIST_DIR < script\n");
        return 2;
    }
    RunDir  = argv[1];
    DistDir = argv[2];
    memset(&Dist, 0, sizeof(Dist));
    while (fgets(line, sizeof(line), stdin))
    {
        char      word[32];
        int       skip = 0;
        long long now  = 0;
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
        if (strcmp(word, "authority") == 0)
        {
            Unhex(rest, Dist.Keys.AuthorityPub, 32);
            Dist.Keys.HaveAuthority = 1;
            continue;
        }
        if (strcmp(word, "instance") == 0)
        {
            uint8_t seed[32];
            Unhex(rest, seed, 32);
            memcpy(Config.InstanceSeed, seed, 32);
            PP_Run_SetInstanceSeed(&Dist.Keys, seed);
            continue;
        }
        if (strcmp(word, "anchor") == 0)
        {
            Config.AnchorLen = Unhex(rest, AnchorDoc, sizeof(AnchorDoc));
            Config.Anchor    = AnchorDoc;
            continue;
        }
        if (strcmp(word, "stale") == 0)
        {
            Config.MonitorStale = (uint32_t)strtoul(rest, NULL, 10);
            continue;
        }
        if (strcmp(word, "bring") == 0 || strcmp(word, "boot_release") == 0)
        {
            size_t             n   = Unhex(rest, Statements[NStatements], sizeof(Statements[0]));
            PP_AppStatement_t *out = word[0] == 'b' && word[1] == 'r' ? &Config.Brought[Config.NBrought++]
                                                                       : &Config.Boot[Config.NBoot++];
            if (PP_AppDist_ReadStatement(Statements[NStatements++], n, out) != 0)
            {
                fprintf(stderr, "dist_check: not a statement file\n");
                return 2;
            }
            continue;
        }
        if (strcmp(word, "start") == 0)
        {
            int record = RecordState, copy = CopyState;
            if (sscanf(rest, "%d %d %lld %lld", &Config.ExpiryResponse, &Config.LostFloor, &Config.MinSeq, &now) != 4)
            {
                return 2;
            }
            Dist.Store = (PP_AppStore_t){NULL, SaveRecord, SaveCopy, WriteFile, ReadFile, LoadTable};
            Dist.Io    = &Io; /* a new run's files are begun by the start, which writes install.jsonl */
            if (record != PP_APP_STORE_ABSENT)
            {
                memcpy(&Dist.Record, &SavedRecord, sizeof(SavedRecord));
                if (record == PP_APP_STORE_READ &&
                    (Dist.Record.Magic != PP_APP_RECORD_MAGIC || Dist.Record.Size != sizeof(Dist.Record) ||
                     !PP_Run_StateValid(&Dist.Record.Run)))
                {
                    record = PP_APP_STORE_LOST;
                }
            }
            if (copy != PP_APP_STORE_ABSENT)
            {
                memcpy(&Dist.Copy, &SavedCopy, sizeof(SavedCopy));
                if (copy == PP_APP_STORE_READ && (Dist.Copy.Magic != PP_APP_COPY_MAGIC || Dist.Copy.Size != sizeof(Dist.Copy)))
                {
                    copy = PP_APP_STORE_LOST;
                }
            }
            if (PP_AppDist_Start(&Dist, &Config, record, copy, 0, now) != 0)
            {
                printf("refused-start\n");
                continue;
            }
            if (record == PP_APP_STORE_READ)
            {
                (void)PP_Run_Recover(&Dist.Record.Run, &Io);
            }
            else
            {
                (void)PP_AppDist_SaveRun(&Dist);
            }
            (void)PP_AppDist_LoadActive(&Dist);
            PrintStep();
        }
        else if (strcmp(word, "frame") == 0)
        {
            if (sscanf(rest, "%s %u %lld", a, &now_ms, &now) != 3)
            {
                return 2;
            }
            size_t n = Unhex(a, bytes, sizeof(bytes));
            PP_AppDist_Frame(&Dist, bytes, n, now_ms, now);
            PrintStep();
        }
        else if (strcmp(word, "control") == 0)
        {
            uint8_t sig[64];
            if (sscanf(rest, "%s %s %u %lld", a, b, &now_ms, &now) != 4)
            {
                return 2;
            }
            size_t n = Unhex(a, bytes, sizeof(bytes));
            memset(sig, 0, sizeof(sig));
            Unhex(b, sig, 64);
            PP_AppDist_Control(&Dist, bytes, n, sig, now_ms, now);
            PrintStep();
        }
        else if (strcmp(word, "tick") == 0)
        {
            if (sscanf(rest, "%u %lld", &now_ms, &now) != 2)
            {
                return 2;
            }
            PP_AppDist_Tick(&Dist, now_ms, now);
            PrintStep();
        }
        else if (strcmp(word, "rollback") == 0)
        {
            PP_AppDist_Rollback(&Dist, strtoll(rest, NULL, 10));
            PrintStep();
        }
        else if (strcmp(word, "beat") == 0)
        {
            PP_AppDist_Beat(&Dist, strtoll(rest, NULL, 10));
            PrintStep();
        }
        else if (strcmp(word, "propose") == 0)
        {
            PP_AppDecision_t d;
            int              ok = 1;
            unsigned         fc = 0;
            PP_AppCommand_t  command;
            if (sscanf(rest, "%s %d %s %lld %u", a, &ok, b, &now, &fc) < 4 || fc > 127)
            {
                return 2;
            }
            size_t n = Unhex(a, bytes, sizeof(bytes));
            PP_Kernel_SetMonitorOk(ok);
            if (n > 6)
            {
                bytes[6] = (uint8_t)ok; /* the app writes its own reading of the monitor into the byte it decides */
            }
            command.MsgId   = PROPOSED_MID;
            command.FcnCode = (uint8_t)fc;
            command.Size    = (uint16_t)(8u + n); /* a command header, then the payload */
            PP_AppDist_Propose(&Dist, &Io, bytes, n, &command,
                               strcmp(b, "-") == 0 ? PP_AGE_NONE : (uint32_t)strtoul(b, NULL, 10), now, &d);
            PrintStep();
            printf("decision %u %u %d %u %d %d %llu %d %d %d\n", d.Kind, d.Cause, d.Rule, d.Basis, d.Held, d.Receipted,
                   (unsigned long long)d.Receipt, d.NotEnacted, d.RecordError, d.Escalated);
            if (d.Escalated)
            {
                int i;
                printf("escalation ");
                for (i = 0; i < 32; i++)
                {
                    printf("%02x", d.EscalationReceipt[i]);
                }
                printf("\n");
            }
        }
        else if (strcmp(word, "reset") == 0 || strcmp(word, "power") == 0)
        {
            PP_AppStore_t keys_store = Dist.Store;
            PP_RunKeys_t  keys       = Dist.Keys;
            memset(&Dist, 0xA5, sizeof(Dist)); /* the app's memory is lost */
            memset(&Dist, 0, sizeof(Dist));
            Dist.Store = keys_store;
            Dist.Keys  = keys;
            PP_Kernel_Deactivate();
            if (word[0] == 'p')
            {
                RecordState = CopyState = PP_APP_STORE_ABSENT; /* a power on reset clears the Critical Data Store */
            }
            printf("records\nstep 0 0 0 0 0 0 0 0 0 0\n");
        }
        else if (strcmp(word, "lose") == 0)
        {
            if (strcmp(rest, "record") == 0)
            {
                SavedRecord.Magic ^= 1u;
            }
            else
            {
                SavedCopy.Magic ^= 1u;
            }
            printf("records\nstep 0 0 0 0 0 0 0 0 0 0\n");
        }
        else if (strcmp(word, "older") == 0)
        {
            Older();
            printf("records\nstep 0 0 0 0 0 0 0 0 0 0\n");
        }
        else if (strcmp(word, "unlink") == 0)
        {
            char path[1024];
            snprintf(path, sizeof(path), "%s/%s", DistDir, rest);
            (void)unlink(path);
            printf("records\nstep 0 0 0 0 0 0 0 0 0 0\n");
        }
        else if (strcmp(word, "tblfail") == 0)
        {
            TableFails = atoi(rest);
            printf("records\nstep 0 0 0 0 0 0 0 0 0 0\n");
        }
        else if (strcmp(word, "groundload") == 0)
        {
            memset(&ground, 0, sizeof(ground));
            Unhex(rest, (uint8_t *)&ground, sizeof(ground));
            printf("validation %d\n", PP_AppDist_ValidateTable(&Dist, &ground));
        }
        else if (strcmp(word, "seal") == 0)
        {
            printf("sealed %d\n", PP_Run_Seal(&Dist.Record.Run, &Io, &Dist.Keys, strtoull(rest, NULL, 10)));
            (void)PP_AppDist_SaveRun(&Dist);
        }
        else if (strcmp(word, "state") == 0)
        {
            printf("state %d %lld %lld %d %d %d\n", Dist.Pep.d.has_active, Dist.Pep.d.has_active ? Dist.Pep.d.active.seq : 0,
                   Dist.Pep.d.floor_seq, Dist.Pep.locked, Dist.Pep.held, PP_Kernel_Active());
        }
        else if (strcmp(word, "held") == 0)
        {
            int k, j;
            printf("held");
            for (k = 0; k < PP_SETS; k++)
            {
                printf(" ");
                if (Dist.Pep.d.has_install && Dist.Pep.d.install.sets[k].held && !Dist.Pep.set_lost[k])
                {
                    for (j = 0; j < 32; j++)
                    {
                        printf("%02x", Dist.Pep.d.install.sets[k].envelope_id[j]);
                    }
                }
                else
                {
                    printf("-");
                }
            }
            printf("\n");
        }
        else if (strcmp(word, "service") == 0)
        {
            printf("service %u\n", (unsigned)TableService.Version);
        }
        else if (strcmp(word, "sizes") == 0)
        {
            printf("sizes %zu %zu %zu %zu\n", sizeof(PP_AppDist_t), sizeof(pp_pep_machine), sizeof(PP_AppRecord_t),
                   sizeof(PP_AppInstallCopy_t));
        }
        else
        {
            fprintf(stderr, "dist_check: unknown line %s\n", word);
            return 2;
        }
        fflush(stdout);
    }
    return 0;
}
