/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */

/**
 * @file
 *   The decision core of the PrismPath cFS app. See prismpath_app_kernel.h.
 *
 * This is the only translation unit that includes ppt_eval.h. The header keeps the table image and the
 * register file in file scope statics, so there is exactly one active image per app, and a candidate image
 * is checked by loading it into that same buffer and putting the active image back afterwards.
 */
#define TBL_MAX        PRISMPATH_APP_IMAGE_MAX
#define PPT_MAX_FIELDS 16
#define STACK_MAX      32

#include "prismpath_app_kernel.h"
#include "prismpath_app_layout.h"
#include "ppt_eval.h"

/* ----------------------------------------------------------------- the reading layout */
enum
{
    LK_INT  = 0,
    LK_BOOL = 1
};

typedef struct
{
    const char *Name;
    uint8_t     Kind;
    uint8_t     Offset;
    uint8_t     Width;
    int32_t     Min;
    int32_t     Max;
} FieldDef_t;

#define FIELD_ROW(reg, name, kind, off, width, lo, hi) {name, LK_##kind, off, width, lo, hi},
static const FieldDef_t k_Fields[PRISMPATH_APP_FIELD_COUNT] = {PRISMPATH_APP_FIELDS(FIELD_ROW)};

/* the text policy/gen_image.py hashes: `name:int:min:max;` or `name:bool;` per field */
static uint32_t Hash_Char(uint32_t h, char c)
{
    return (h ^ (uint8_t)c) * 0x01000193u;
}

static uint32_t Hash_Str(uint32_t h, const char *s)
{
    while (*s != '\0')
    {
        h = Hash_Char(h, *s++);
    }
    return h;
}

static uint32_t Hash_Int(uint32_t h, int32_t v)
{
    char     digits[12];
    uint32_t mag = (v < 0) ? (uint32_t)0 - (uint32_t)v : (uint32_t)v;
    int      n   = 0;

    if (v < 0)
    {
        h = Hash_Char(h, '-');
    }
    do
    {
        digits[n++] = (char)('0' + (mag % 10u));
        mag /= 10u;
    } while (mag != 0u);
    while (n > 0)
    {
        h = Hash_Char(h, digits[--n]);
    }
    return h;
}

uint32_t PP_Kernel_LayoutHash(void)
{
    uint32_t h = 0x811C9DC5u;
    int      i;

    for (i = 0; i < PRISMPATH_APP_FIELD_COUNT; i++)
    {
        h = Hash_Str(h, k_Fields[i].Name);
        if (k_Fields[i].Kind == LK_BOOL)
        {
            h = Hash_Str(h, ":bool;");
        }
        else
        {
            h = Hash_Str(h, ":int:");
            h = Hash_Int(h, k_Fields[i].Min);
            h = Hash_Char(h, ':');
            h = Hash_Int(h, k_Fields[i].Max);
            h = Hash_Char(h, ';');
        }
    }
    return h;
}

/* ----------------------------------------------------------------- the active image */
static uint8_t   Active_Image[PRISMPATH_APP_IMAGE_MAX];
static uint16_t  Active_Len;
static PP_Rule_t Active_Rules[PRISMPATH_APP_MAX_RULES];
static uint16_t  Active_RuleCount;
static uint16_t  Active_ContractCause;
static uint16_t  Active_NoMatchCause;
static int       Active_Valid;

static void Restore_Active(void)
{
    if (Active_Valid)
    {
        memcpy(tbl, Active_Image, Active_Len);
        (void)parse_table(Active_Len);
    }
}

/* the registered causes the checks answer with (prismpath/kernel/causes.py) */
enum
{
    C_CAPS       = 16,
    C_SHORT      = 69,
    C_BAD_MAGIC  = 70,
    C_BAD_VER    = 71,
    C_LENGTH     = 73,
    C_UNKNOWN_OP = 74,
    C_UNKNOWN_TY = 75,
    C_FIELD_OOB  = 76,
    C_EDGE_OOB   = 77,
    C_PROG_OOB   = 78,
    C_OPCODE     = 79,
    C_ATOM_OOB   = 80,
    C_UNK_FIELD  = 85
};

/* one edge's program, as a stack machine on depths only: every operand present, nothing left but the result */
static int Check_Prog(uint16_t Off, uint16_t Cnt)
{
    int sp = 0;
    uint16_t i;

    if (Cnt == 0 || (uint32_t)Off + Cnt > prog_len)
    {
        return (Cnt == 0) ? C_OPCODE : C_PROG_OOB;
    }
    for (i = 0; i < Cnt; i++)
    {
        uint16_t word = rd16b(tbl + prog_off_base + 2u * (uint32_t)(Off + i));
        if (word < 0x8000u)
        {
            if (word >= n_atoms)
            {
                return C_ATOM_OOB;
            }
            sp++;
        }
        else if (word == OPC_NOT)
        {
            if (sp < 1)
            {
                return C_OPCODE;
            }
        }
        else if (word == OPC_AND || word == OPC_OR)
        {
            if (sp < 2)
            {
                return C_OPCODE;
            }
            sp--;
        }
        else if (word == OPC_TRUE || word == OPC_FALSE)
        {
            sp++;
        }
        else
        {
            return C_OPCODE;
        }
        if (sp > STACK_MAX)
        {
            return C_CAPS;
        }
    }
    return (sp == 1) ? 0 : C_OPCODE;
}

/* load the candidate into the evaluator's buffer and check it; leaves the candidate loaded when it passes */
static int Check_Loaded(const PP_PolicyTable_t *Table)
{
    uint32_t need;
    uint16_t i;
    int      rc;

    if (Table->ImageLen > PRISMPATH_APP_IMAGE_MAX)
    {
        return C_CAPS;
    }
    if (Table->ImageLen < 28u)
    {
        return C_SHORT;
    }
    memcpy(tbl, Table->Image, Table->ImageLen);
    if ((uint32_t)rd32(tbl) != PPT_MAGIC)
    {
        return C_BAD_MAGIC;
    }
    if (rd16b(tbl + 4) != 1u)
    {
        return C_BAD_VER;
    }
    switch (parse_table(Table->ImageLen))
    {
        case PPT_PARSE_OK:
            break;
        case PPT_PARSE_CAPS:
            return C_CAPS;
        default:
            return C_LENGTH;
    }
    /* exactly the sections the header counts, and no section this app does not read */
    need = 28u + 8u * n_atoms + 4u * n_nodes + 6u * n_edges + 2u * prog_len;
    if (tbl_flags & 1u)
    {
        need += 2u * n_nodes;
    }
    if (need != Table->ImageLen || (tbl_flags & 0xFFFEu) != 0u)
    {
        return C_LENGTH;
    }
    if (n_fields != PRISMPATH_APP_FIELD_COUNT || visits_idx != PPT_VISITS_NONE ||
        Table->LayoutHash != PP_Kernel_LayoutHash())
    {
        return C_UNK_FIELD;
    }
    for (i = 0; i < n_atoms; i++)
    {
        const uint8_t *atom = tbl + atoms_off + 8u * i;
        if (rd16b(atom) >= n_fields)
        {
            return C_FIELD_OOB;
        }
        if (atom[2] > OP_TRUTHY)
        {
            return C_UNKNOWN_OP;
        }
        if (atom[3] != TY_NONE && atom[3] != TY_BOOL && atom[3] != TY_INT)
        {
            return C_UNKNOWN_TY;
        }
    }
    for (i = 0; i < n_nodes; i++)
    {
        const uint8_t *node = tbl + nodes_off + 4u * i;
        if ((uint32_t)rd16b(node) + rd16b(node + 2) > n_edges)
        {
            return C_EDGE_OOB;
        }
    }
    for (i = 0; i < n_edges; i++)
    {
        const uint8_t *edge = tbl + edges_off + 6u * i;
        if (rd16b(edge) >= n_nodes || node_edge_count(rd16b(edge)) != 0u)
        {
            return C_EDGE_OOB; /* every rule's target is a terminal node, so the matched edge names the rule */
        }
        rc = Check_Prog(rd16b(edge + 2), rd16b(edge + 4));
        if (rc != 0)
        {
            return rc;
        }
    }
    /* the rules: one per edge of the start node, each an action the app knows */
    if (Table->RuleCount == 0 || Table->RuleCount > PRISMPATH_APP_MAX_RULES ||
        node_edge_count(start_node) != Table->RuleCount)
    {
        return C_SHORT;
    }
    for (i = 0; i < Table->RuleCount; i++)
    {
        const PP_Rule_t *rule = &Table->Rules[i];
        if (rule->Kind > PP_KIND_ESCALATE || (rule->Kind == PP_KIND_ALLOW) != (rule->Cause == 0u))
        {
            return C_SHORT;
        }
    }
    if (Table->ContractCause == 0u || Table->NoMatchCause == 0u)
    {
        return C_SHORT;
    }
    return 0;
}

int PP_Kernel_Check(const PP_PolicyTable_t *Table)
{
    int rc = Check_Loaded(Table);

    Restore_Active();
    return rc;
}

int PP_Kernel_Activate(const PP_PolicyTable_t *Table)
{
    int rc = Check_Loaded(Table);

    if (rc != 0)
    {
        Restore_Active();
        return rc;
    }
    memcpy(Active_Image, Table->Image, Table->ImageLen);
    Active_Len = Table->ImageLen;
    memcpy(Active_Rules, Table->Rules, sizeof(Active_Rules));
    Active_RuleCount     = Table->RuleCount;
    Active_ContractCause = Table->ContractCause;
    Active_NoMatchCause  = Table->NoMatchCause;
    Active_Valid         = 1;
    return 0;
}

int PP_Kernel_Active(void)
{
    return Active_Valid;
}

const char *PP_Kernel_FieldName(int16_t Field)
{
    return (Field >= 0 && Field < PRISMPATH_APP_FIELD_COUNT) ? k_Fields[Field].Name : "-";
}

static void Refuse(PP_Verdict_t *V, uint16_t Cause, int16_t Field, uint8_t Reason)
{
    V->Kind   = PP_KIND_REFUSE;
    V->Reason = Reason;
    V->Cause  = Cause;
    V->Rule   = -1;
    V->Field  = Field;
}

int PP_Kernel_FieldValue(const uint8_t *Payload, size_t PayloadLen, int Field, int32_t *Value, int *IsBool)
{
    const FieldDef_t *def;

    if (Field < 0 || Field >= PRISMPATH_APP_FIELD_COUNT)
    {
        return 0;
    }
    def = &k_Fields[Field];
    if ((size_t)def->Offset + def->Width > PayloadLen)
    {
        return 0;
    }
    if (def->Width == 1u)
    {
        *Value = Payload[def->Offset];
    }
    else
    {
        /* the payload is little endian, as the layout header says */
        *Value = (int32_t)(uint16_t)(Payload[def->Offset] | ((uint16_t)Payload[def->Offset + 1u] << 8));
    }
    *IsBool = (def->Kind == LK_BOOL);
    return 1;
}

void PP_Kernel_Decide(const uint8_t *Payload, size_t PayloadLen, PP_Verdict_t *Verdict)
{
    int      i;
    uint16_t target = 0;
    uint8_t  err    = 0;
    int8_t   edge;

    if (!Active_Valid)
    {
        Refuse(Verdict, PP_NO_IMAGE_CAUSE, -1, PP_REASON_NONE);
        return;
    }
    /* the boundary, field by field in register order: the first field missing, of the wrong type or out of
     * range is the refusal, before any rule is read */
    for (i = 0; i < PRISMPATH_APP_FIELD_COUNT; i++)
    {
        const FieldDef_t *def = &k_Fields[i];
        int32_t           value;
        int               is_bool;

        if (!PP_Kernel_FieldValue(Payload, PayloadLen, i, &value, &is_bool))
        {
            Refuse(Verdict, Active_ContractCause, (int16_t)i, PP_REASON_MISSING);
            return;
        }
        if (value < def->Min || value > def->Max)
        {
            Refuse(Verdict, Active_ContractCause, (int16_t)i, is_bool ? PP_REASON_WRONG_TYPE : PP_REASON_OUT_OF_RANGE);
            return;
        }
        set_reg_typed((uint16_t)i, is_bool ? TY_BOOL : TY_INT, value);
    }
    edge = evaluate(start_node, &target, &err);
    if (err != 0u || edge < 0 || (uint16_t)edge >= Active_RuleCount)
    {
        Refuse(Verdict, Active_NoMatchCause, -1, PP_REASON_NONE);
        return;
    }
    Verdict->Kind   = Active_Rules[edge].Kind;
    Verdict->Reason = PP_REASON_NONE;
    Verdict->Cause  = Active_Rules[edge].Cause;
    Verdict->Rule   = edge;
    Verdict->Field  = -1;
}
