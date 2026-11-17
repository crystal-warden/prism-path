/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/* Host check of the app's decision core (prismpath_app_kernel.c), with no cFS in it.
 *
 *   kernel_check <vectors.txt>
 *
 * The table is built from the same generated include the cFE table uses. Each vector line is
 *   cmd_class ground_contact slew_deg thrust_pct kind cause
 * (kind 0 allow, 1 refuse, 2 escalate), the Python reference decision path's answer for that reading, and the
 * kernel must give the same kind and cause. A reading is sent as the payload bytes the layout defines.
 * Then the image is corrupted every way a byte can be corrupted. The checks are structural, so a flip that
 * leaves the image well formed (a different threshold, say) is accepted, and a signature is what catches that
 * (a later work package); every other flip must be refused, and a refused candidate must leave the active
 * image deciding exactly as before. Build with -fsanitize=undefined. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prismpath_app_kernel.c"

#include "prismpath_app_policy_image.inc"

static PP_PolicyTable_t Good = {
    .LayoutHash    = PRISMPATH_APP_EXAMPLE_LAYOUT_HASH,
    .ImageLen      = PRISMPATH_APP_EXAMPLE_IMAGE_LEN,
    .RuleCount     = PRISMPATH_APP_EXAMPLE_RULE_COUNT,
    .ContractCause = PRISMPATH_APP_EXAMPLE_CONTRACT_CAUSE,
    .NoMatchCause  = PRISMPATH_APP_EXAMPLE_NOMATCH_CAUSE,
    .Rules         = PRISMPATH_APP_EXAMPLE_RULES,
    .Image         = PRISMPATH_APP_EXAMPLE_IMAGE,
};

static int Failures;

#define CHECK(cond, ...)                      \
    do                                        \
    {                                         \
        if (!(cond))                          \
        {                                     \
            Failures++;                       \
            printf("FAIL: " __VA_ARGS__);     \
            printf("\n");                     \
        }                                     \
    } while (0)

static void Payload(uint8_t *p, int cls, int gc, int slew, int thrust)
{
    memset(p, 0, PRISMPATH_APP_PAYLOAD_LEN);
    p[0] = (uint8_t)cls;
    p[1] = (uint8_t)gc;
    p[2] = (uint8_t)(slew & 0xFF);
    p[3] = (uint8_t)(slew >> 8);
    p[4] = (uint8_t)(thrust & 0xFF);
    p[5] = (uint8_t)(thrust >> 8);
}

static unsigned Digest(void)
{
    /* a digest of the decisions on a fixed set of readings, to see an active image is unchanged */
    unsigned     h = 2166136261u;
    int          cls, slew, thrust;
    uint8_t      p[PRISMPATH_APP_PAYLOAD_LEN];
    PP_Verdict_t v;

    for (cls = 0; cls < 12; cls++)
    {
        for (slew = 0; slew <= 200; slew += 20)
        {
            for (thrust = 0; thrust <= 210; thrust += 30)
            {
                Payload(p, cls, slew & 1, slew, thrust);
                PP_Kernel_Decide(p, sizeof(p), &v);
                h = (h ^ v.Kind) * 16777619u;
                h = (h ^ v.Cause) * 16777619u;
                h = (h ^ (unsigned)(v.Rule + 1)) * 16777619u;
            }
        }
    }
    return h;
}

int main(int argc, char **argv)
{
    FILE        *f;
    int          cls, gc, slew, thrust, kind, cause, n = 0, accepted = 0, refused = 0, i, rc;
    uint8_t      p[PRISMPATH_APP_PAYLOAD_LEN];
    PP_Verdict_t v;
    unsigned     base;
    static PP_PolicyTable_t Bad;

    if (argc != 2)
    {
        fprintf(stderr, "usage: kernel_check vectors.txt\n");
        return 2;
    }

    /* no image: every reading is refused, with the no image cause */
    Payload(p, 1, 0, 30, 0);
    PP_Kernel_Decide(p, sizeof(p), &v);
    CHECK(v.Kind == PP_KIND_REFUSE && v.Cause == PP_NO_IMAGE_CAUSE, "no image must refuse (kind %d cause %d)", v.Kind, v.Cause);

    CHECK(PP_Kernel_LayoutHash() == PRISMPATH_APP_EXAMPLE_LAYOUT_HASH, "layout hash %08x != generated %08x",
          PP_Kernel_LayoutHash(), (unsigned)PRISMPATH_APP_EXAMPLE_LAYOUT_HASH);
    rc = PP_Kernel_Check(&Good);
    CHECK(rc == 0, "the example table must pass the checks (cause %d)", rc);
    CHECK(!PP_Kernel_Active(), "a check alone must not activate");
    rc = PP_Kernel_Activate(&Good);
    CHECK(rc == 0 && PP_Kernel_Active(), "the example table must activate (cause %d)", rc);

    f = fopen(argv[1], "r");
    if (f == NULL)
    {
        perror("vectors");
        return 2;
    }
    while (fscanf(f, "%d %d %d %d %d %d", &cls, &gc, &slew, &thrust, &kind, &cause) == 6)
    {
        Payload(p, cls, gc, slew, thrust);
        PP_Kernel_Decide(p, sizeof(p), &v);
        CHECK(v.Kind == kind && v.Cause == cause, "reading %d %d %d %d: reference kind %d cause %d, kernel kind %d cause %d",
              cls, gc, slew, thrust, kind, cause, v.Kind, v.Cause);
        n++;
    }
    fclose(f);
    printf("%d vectors compared with the reference\n", n);
    CHECK(n > 1000, "too few vectors (%d)", n);

    /* a payload shorter than the layout is the core's boundary refusal */
    PP_Kernel_Decide(p, PRISMPATH_APP_PAYLOAD_LEN - 1, &v);
    CHECK(v.Kind == PP_KIND_REFUSE && v.Cause == PRISMPATH_APP_EXAMPLE_CONTRACT_CAUSE, "short payload must refuse");

    base = Digest();

    /* every single byte of the image corrupted three ways, and every truncation */
    for (i = 0; i < PRISMPATH_APP_EXAMPLE_IMAGE_LEN; i++)
    {
        static const uint8_t flips[3] = {0x01, 0x80, 0xFF};
        int                  k;
        for (k = 0; k < 3; k++)
        {
            Bad = Good;
            Bad.Image[i] ^= flips[k];
            rc = PP_Kernel_Check(&Bad);
            CHECK(Digest() == base, "a check of a corrupted image (byte %d) changed the active image", i);
            if (rc == 0)
            {
                /* structurally well formed (a different constant, say): it may run, within bounds, and must not crash */
                accepted++;
                CHECK(PP_Kernel_Activate(&Bad) == 0, "check and activate disagree at byte %d", i);
                (void)Digest();
                CHECK(PP_Kernel_Activate(&Good) == 0, "reactivating the good image failed");
            }
            else
            {
                refused++;
                CHECK(PP_Kernel_Activate(&Bad) == rc, "activate must refuse what check refused (byte %d)", i);
                CHECK(Digest() == base, "a refused activation (byte %d) changed the active image", i);
            }
        }
    }
    for (i = 0; i < PRISMPATH_APP_EXAMPLE_IMAGE_LEN; i++)
    {
        Bad          = Good;
        Bad.ImageLen = (uint16_t)i;
        CHECK(PP_Kernel_Check(&Bad) != 0, "a truncated image (%d bytes) must be refused", i);
        CHECK(Digest() == base, "a refused truncation changed the active image");
    }
    Bad          = Good;
    Bad.ImageLen = PRISMPATH_APP_IMAGE_MAX + 1;
    CHECK(PP_Kernel_Check(&Bad) == 16, "an image longer than the table must be refused with caps-exceeded");
    Bad            = Good;
    Bad.LayoutHash ^= 1u;
    CHECK(PP_Kernel_Check(&Bad) == 85, "an image for another layout must be refused with envelope:unknown-field");
    Bad            = Good;
    Bad.RuleCount  = (uint16_t)(Good.RuleCount - 1);
    CHECK(PP_Kernel_Check(&Bad) != 0, "rules that do not match the edges must be refused");
    Bad            = Good;
    Bad.Rules[0].Kind = 3;
    CHECK(PP_Kernel_Check(&Bad) != 0, "an unknown rule kind must be refused");
    Bad            = Good;
    Bad.Rules[5].Cause = 7;
    CHECK(PP_Kernel_Check(&Bad) != 0, "an allow rule that carries a cause must be refused");
    CHECK(Digest() == base, "the active image changed");
    printf("%d corruptions refused, %d well formed ones accepted and run, none escaped\n", refused, accepted);
    CHECK(refused > 100, "too few corruptions refused (%d)", refused);

    printf(Failures == 0 ? "kernel_check: all checks passed\n" : "kernel_check: %d FAILED\n", Failures);
    return Failures == 0 ? 0 : 1;
}
