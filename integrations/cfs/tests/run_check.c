/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* Host check of the app's receipts (prismpath_app_run.c) and its decision core, with no cFS in it.
 *
 *   run_check OUT TABLE AUTHORITY_PUB INSTANCE_SEED PAYLOADS TIME_US [--reset-at N] [--hold FROM UNTIL]
 *             [--refuse TABLE CAUSE]...
 *
 * TABLE is the signed struct bytes of a policy table, AUTHORITY_PUB the raw public key, INSTANCE_SEED the raw 32
 * byte seed, PAYLOADS one payload per line in hex (an empty line is an empty payload). The table is checked and
 * activated as the app does, every payload is decided and recorded into the run directory OUT through stdio, and
 * the run is sealed at TIME_US. With --reset-at N a processor reset is simulated before payload N: the state is
 * copied out as the Critical Data Store holds it, the app's copy is scribbled over, a torn write is left on two
 * run files (bytes after the recorded lengths), and the state is restored from the copy, held valid, and the
 * files recovered; the table is then checked again against the restored floor, as the app's initial load is.
 * With --hold FROM UNTIL the payloads from FROM up to UNTIL are decided while held (X7), which opens a case of their
 * own marked "hold":true and another when the hold ends. Each --refuse TABLE CAUSE must be refused by the signed
 * table checks of PP_Run_CheckSignedTable with that cause (an older version, a tampered table). The table is also
 * held to PP_Run_CheckTable, the checks of a table a distribution envelope admits: its own body hash passes, another
 * is dist:body-mismatch and a changed image attestation sig:invalid. Prints the receipt count and the root, then
 * "run_check: all checks passed". */
#define _XOPEN_SOURCE 700 /* truncate */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "prismpath_app_kernel.c"
#include "prismpath_app_run.c"

static int Failures;
#define CHECK(cond, ...)                  \
    do                                    \
    {                                     \
        if (!(cond))                      \
        {                                 \
            Failures++;                   \
            printf("FAIL: " __VA_ARGS__); \
            printf("\n");                 \
        }                                 \
    } while (0)

/* ----------------------------------------------------------------- stdio files */
static const char *Dir;
static FILE       *Handles[8];

static void PathOf(int File, char *Out, size_t Cap)
{
    snprintf(Out, Cap, "%s/%s", Dir, PP_RunFileNames[File]);
}

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
    PathOf(File, path, sizeof(path));
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
    PathOf(File, path, sizeof(path));
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
    PathOf(File, path, sizeof(path));
    return truncate(path, (off_t)Len) == 0 ? 0 : -1;
}

static const PP_RunIo_t Io = {NULL, IoOpen, IoWrite, IoRead, IoClose, IoSize, IoTruncate};

/* ----------------------------------------------------------------- inputs */
static size_t ReadFile(const char *Path, void *Out, size_t Cap)
{
    FILE  *f = fopen(Path, "rb");
    size_t n;

    if (f == NULL)
    {
        printf("cannot read %s\n", Path);
        exit(2);
    }
    n = fread(Out, 1, Cap, f);
    fclose(f);
    return n;
}

static int Hex(char c)
{
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

static PP_PolicyTable_t Table, Other;
static PP_RunState_t    State, Cds;
static PP_RunKeys_t     Keys;

static void Torn(int File)
{
    int32_t h = IoOpen(NULL, File, PP_IO_APPEND);
    (void)IoWrite(NULL, h, "torn", 4);
    IoClose(NULL, h);
}

int main(int argc, char **argv)
{
    uint8_t  digest[32], seed[32], root[32];
    char     line[256];
    FILE    *payloads;
    long     reset_at = -1;
    long     hold_from = -1, hold_until = -1;
    long     n        = 0;
    int      i;
    uint64_t index;

    if (argc < 7)
    {
        printf("usage: run_check OUT TABLE AUTHORITY_PUB INSTANCE_SEED PAYLOADS TIME_US [--reset-at N] [--refuse TABLE CAUSE]...\n");
        return 2;
    }
    Dir = argv[1];
    CHECK(ReadFile(argv[2], &Table, sizeof(Table)) == sizeof(Table), "the table file is not %zu bytes", sizeof(Table));
    CHECK(ReadFile(argv[3], Keys.AuthorityPub, 32) == 32, "the authority key is not 32 bytes");
    Keys.HaveAuthority = 1;
    CHECK(ReadFile(argv[4], seed, 32) == 32, "the instance seed is not 32 bytes");
    PP_Run_SetInstanceSeed(&Keys, seed);
    for (i = 7; i < argc; i++)
    {
        if (strcmp(argv[i], "--reset-at") == 0 && i + 1 < argc)
        {
            reset_at = atol(argv[++i]);
        }
        if (strcmp(argv[i], "--hold") == 0 && i + 2 < argc)
        {
            hold_from  = atol(argv[++i]);
            hold_until = atol(argv[++i]);
        }
    }

    PP_Run_Init(&State);
    CHECK(PP_Run_StateValid(&State), "a fresh state is not valid");
    CHECK(PP_Run_Begin(&Io) == 0, "cannot begin the run files in %s", Dir);
    CHECK(PP_Kernel_Check(&Table) == 0, "the kernel refuses the table");
    CHECK(PP_Run_CheckSignedTable(&State, &Keys, &Table, digest) == 0, "the run checks refuse the signed table");
    {
        /* the checks of a table its envelope admits: the body hash it signed, and the image attestation */
        uint8_t body[32], other[32];
        memcpy(body, digest, 32);
        CHECK(PP_Run_CheckTable(&Keys, &Table, body, other) == 0 && memcmp(other, digest, 32) == 0,
              "the envelope checks refuse the table its body hash names");
        body[0] ^= 1;
        CHECK(PP_Run_CheckTable(&Keys, &Table, body, other) == R_BODY_MISMATCH, "another body hash admits the table");
        body[0] ^= 1;
        Other = Table;
        Other.ImageSig[0] ^= 1;
        CHECK(PP_Run_CheckTable(&Keys, &Other, body, other) == R_SIG_INVALID, "a changed image attestation passes");
        printf("envelope checks: the body hash and the image attestation\n");
    }
    CHECK(PP_Kernel_Activate(&Table) == 0, "the table does not activate");
    PP_Run_Accept(&State, Table.Version, digest);

    payloads = fopen(argv[5], "r");
    if (payloads == NULL)
    {
        printf("cannot read %s\n", argv[5]);
        return 2;
    }
    while (fgets(line, sizeof(line), payloads) != NULL)
    {
        uint8_t      p[64];
        size_t       len = 0;
        char        *c   = line;
        PP_Verdict_t v;

        while (Hex(c[0]) >= 0 && Hex(c[1]) >= 0 && len < sizeof(p))
        {
            p[len++] = (uint8_t)(Hex(c[0]) * 16 + Hex(c[1]));
            c += 2;
        }
        if (n == reset_at)
        {
            /* the processor reset: the CDS keeps its copy, the app's own memory is lost */
            memcpy(&Cds, &State, sizeof(State));
            memset(&State, 0xA5, sizeof(State));
            CHECK(!PP_Run_StateValid(&State), "scribbled memory reads as a valid state");
            Torn(PP_FILE_RECEIPTS);
            Torn(PP_FILE_STREAM);
            memcpy(&State, &Cds, sizeof(State));
            CHECK(PP_Run_StateValid(&State), "the state restored from the CDS copy is not valid");
            CHECK(PP_Run_Recover(&State, &Io) == 0, "the torn writes were not cut back");
            CHECK(IoSize(NULL, PP_FILE_RECEIPTS) == (int64_t)State.ReceiptsLen, "receipts.jsonl not recovered");
            CHECK(PP_Run_CheckSignedTable(&State, &Keys, &Table, digest) == 0,
                  "the same table is refused against the restored floor");
            printf("reset simulated before payload %ld: %llu receipts restored\n", n,
                   (unsigned long long)State.Acc.count);
        }
        PP_Kernel_Decide(p, len, &v);
        CHECK(PP_Run_Record(&State, &Io, &Keys, &Table, digest, p, len, &v, n >= hold_from && n < hold_until, &index) == 0,
              "payload %ld not recorded", n);
        CHECK(index == (uint64_t)n, "payload %ld got receipt %llu", n, (unsigned long long)index);
        n++;
    }
    fclose(payloads);

    for (i = 7; i < argc; i++)
    {
        if (strcmp(argv[i], "--refuse") == 0 && i + 2 < argc)
        {
            int want = atoi(argv[i + 2]);
            int got;
            CHECK(ReadFile(argv[i + 1], &Other, sizeof(Other)) == sizeof(Other), "%s is not a table", argv[i + 1]);
            got = PP_Kernel_Check(&Other);
            if (got == 0)
            {
                got = PP_Run_CheckSignedTable(&State, &Keys, &Other, digest);
            }
            CHECK(got == want, "%s: refused with cause %d, not %d", argv[i + 1], got, want);
            printf("table %s refused with cause %d\n", argv[i + 1], got);
            i += 2;
        }
    }
    /* a state of another size, or with its magic broken, is not read */
    Cds      = State;
    Cds.Size = Cds.Size + 1u;
    CHECK(!PP_Run_StateValid(&Cds), "a state of another size reads as valid");
    Cds       = State;
    Cds.Magic = 0;
    CHECK(!PP_Run_StateValid(&Cds), "a state without its magic reads as valid");
    Cds           = State;
    Cds.FloorLost = 2u;
    CHECK(!PP_Run_StateValid(&Cds), "a state with a lost floor mark other than 0 or 1 reads as valid");

    /* a store that did not read: the floor is lost, and the mission's response decides what the new run admits */
    PP_Run_Init(&Cds);
    PP_Run_LoseFloor(&Cds, PP_LOST_FLOOR_LOCK, 1u);
    CHECK(PP_Run_StateValid(&Cds), "a locked state is not valid");
    CHECK(PP_Run_CheckSignedTable(&Cds, &Keys, &Table, digest) == R_VERSION_REPLAY, "a locked floor admits the table");
    PP_Run_Accept(&Cds, Table.Version, digest);
    CHECK(PP_Run_CheckSignedTable(&Cds, &Keys, &Table, digest) == R_VERSION_REPLAY, "accepting an image clears the lock");
    for (i = 0; i < 3; i++)
    {
        uint32_t Min  = i == 0 ? 0u : (i == 1 ? Table.Version : Table.Version + 1u);
        int      Want = i == 2 ? R_VERSION_REPLAY : 0;
        PP_Run_Init(&Cds);
        PP_Run_LoseFloor(&Cds, PP_LOST_FLOOR_MINIMUM, Min);
        CHECK(PP_Run_StateValid(&Cds) && Cds.FloorLost == 0u, "a minimum floor state is not valid");
        CHECK(PP_Run_CheckSignedTable(&Cds, &Keys, &Table, digest) == Want, "minimum v%u: the v%u table got the wrong answer",
              (unsigned)Min, (unsigned)Table.Version);
    }
    printf("lost floor: lock refuses, minimum admits from its version\n");

    CHECK(PP_Run_Seal(&State, &Io, &Keys, (uint64_t)strtoull(argv[6], NULL, 10)) == 0, "the seal failed");
    PP_Run_Root(&State, root);
    printf("receipts %llu cases %u root ", (unsigned long long)State.Acc.count, (unsigned)State.CaseCount);
    for (i = 0; i < 32; i++)
    {
        printf("%02x", root[i]);
    }
    printf("\n");
    printf(Failures == 0 ? "run_check: all checks passed\n" : "run_check: %d FAILED\n", Failures);
    return Failures == 0 ? 0 : 1;
}
