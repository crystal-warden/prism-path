/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* Host check of the F Prime guard's C core (PrismPathRef/Guard/GuardCore.c) and the cFS app's decision and receipt
 * code under it, with no F Prime in it.
 *
 *   guard_check POLICY KEYS_DIR RUN_DIR ARGS TIME_US
 *
 * ARGS holds one proposed command per line: the serialized argument bytes in hex, as F Prime serializes them. Each
 * is decided and receipted through GC_Propose, then the run is sealed. Prints one line per proposal,
 * "kind cause rule field receipt", then "root <hex>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "GuardCore.h"

static int Hex(char c)
{
    return (c >= '0' && c <= '9') ? c - '0' : (c >= 'a' && c <= 'f') ? c - 'a' + 10 : -1;
}

int main(int argc, char **argv)
{
    GC      *core = GC_Create();
    char     what[64] = "", line[256], root[65];
    uint32_t version = 0, rules = 0, leaves = 0;
    FILE    *args;
    int      rc;

    if (argc != 6)
    {
        printf("usage: guard_check POLICY KEYS_DIR RUN_DIR ARGS TIME_US\n");
        return 2;
    }
    rc = GC_Load(core, argv[1], argv[2], argv[3], &version, &rules, what);
    if (rc != 0)
    {
        printf("load %d %s\n", rc, what);
        return 1;
    }
    printf("loaded %u %u\n", version, rules);
    args = fopen(argv[4], "r");
    if (args == NULL)
    {
        return 2;
    }
    while (fgets(line, sizeof(line), args) != NULL)
    {
        uint8_t    bytes[64];
        size_t     len = 0;
        char      *c   = line;
        GC_Outcome out;

        while (Hex(c[0]) >= 0 && Hex(c[1]) >= 0 && len < sizeof(bytes))
        {
            bytes[len++] = (uint8_t)(Hex(c[0]) * 16 + Hex(c[1]));
            c += 2;
        }
        GC_Propose(core, bytes, len, &out);
        printf("%d %u %d %s %lld\n", out.Kind, out.Cause, out.Rule, out.Field[0] ? out.Field : "-", (long long)out.Receipt);
    }
    fclose(args);
    rc = GC_Seal(core, (uint64_t)strtoull(argv[5], NULL, 10), &leaves, root);
    printf("seal %d %u\nroot %s\n", rc, leaves, root);
    GC_Destroy(core);
    return rc == 0 ? 0 : 1;
}
