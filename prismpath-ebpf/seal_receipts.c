/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */
/* seal_receipts.c - Merkle-root a persistent receipt journal.
 *
 * The append-only journal (raw ppt_receipt records) is where an OUT-OF-BAND admin swap - the one-shot
 * `loader <new> swapselector <old>` with PPT_RECEIPT_JOURNAL set - deposits its migration receipt. This
 * tool reads the whole journal and Merkle-roots it with the ONE canonical merkle.h helper (leaf =
 * sha256(receipt bytes)), the same leaf format and root the live forwarder and the corpus harnesses
 * use. That root is the anchorable object; the OTS stamp of it is the held-for-publish step.
 *
 *   gcc -O2 -I. seal_receipts.c -o seal_receipts -lcrypto
 *   ./seal_receipts receipts.journal
 */
#include <stdio.h>
#include <stdlib.h>
#include "ppt_common.h"
#include "merkle.h"

#define MAX_J 65536

int main(int argc, char **argv) {
    const char *jp = argc > 1 ? argv[1] : "receipts.journal";
    FILE *f = fopen(jp, "rb");
    if (!f) { fprintf(stderr, "seal_receipts: cannot open %s\n", jp); return 1; }
    static struct ppt_receipt batch[MAX_J];
    int n = 0;
    while (n < MAX_J && fread(&batch[n], sizeof(struct ppt_receipt), 1, f) == 1) n++;
    int more = (fgetc(f) != EOF);
    int truncated = (more && n == MAX_J);   /* the array filled first: the rest of the journal is unread */
    int trailing = (more && !truncated);    /* a partial record at the tail = a torn write */
    fclose(f);

    /* Rooting a prefix and calling it the seal would anchor a trail that is not the trail. */
    if (truncated) {
        fprintf(stderr, "seal_receipts: %s holds more than %d receipts; this build cannot seal it\n",
                jp, MAX_J);
        return 3;
    }

    printf("RECEIPT JOURNAL %s: %d receipt(s)%s\n", jp, n,
           trailing ? "  [WARNING: trailing partial record, torn write]" : "");
    int migrations = 0;
    for (int i = 0; i < n; i++) {
        int is_migr = (batch[i].event == PPT_EVENT_MIGRATION);
        if (is_migr) migrations++;
        printf("  [%d] seq=%llu prev=%d event=%d next=%d cause=%d policy=%016llx%s\n", i,
               (unsigned long long)batch[i].seq, batch[i].prev_node, batch[i].event,
               batch[i].next_node, batch[i].cause, (unsigned long long)batch[i].policy_hash,
               is_migr ? "  (migration)" : "");
    }
    uint8_t root[32]; merkle_root(batch, n, root);
    char hx[65]; for (int i = 0; i < 32; i++) sprintf(hx + 2 * i, "%02x", root[i]);
    printf("  %d migration receipt(s) among %d leaves\n", migrations, n);
    printf("  Merkle root (seal, shared merkle.h): %s\n", hx);
    printf("  (OTS anchor of that root is the held-for-publish step, owner-gated)\n");
    return trailing ? 2 : 0;
}
