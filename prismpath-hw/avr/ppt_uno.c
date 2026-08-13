/* ppt_uno.c — the PPT v1 table interpreter on an ATmega328P (Arduino Uno R3): the MCU substrate.
 *
 * The same certified `.ppt` images every other substrate holds (TABLE_FORMAT.md) are loaded over
 * serial into RAM and evaluated by a byte-exact port of interp.c's evaluator core: atoms are
 * comparators over the field register file, each edge's RPN program folds atom results, first
 * true edge wins. No dynamic allocation, no file IO — the table lives in a static buffer and is
 * evaluated straight from the raw bytes.
 *
 * Serial protocol, 38400 8N1 (host drives; every request gets exactly one reply):
 *   'I'                          -> 'i' + u8 len + ident string
 *   'L' + u16 len + <ppt bytes>  -> 'l' (loaded) | 'E' + u8 code
 *   'V' + u16 len + <regs bytes> -> 'M' + u8 edge + u16 target | 'N' (none) | 'E' + u8 code
 * The 'V' payload is EXACTLY ppt_compile.encode_regs' output (the bytes interp.c's eval mode
 * reads): u32 node_idx, then n_fields x (i32 ty, i32 val), little-endian — AVR is little-endian,
 * so values are read in place.
 *
 * Error codes: 1 bad-magic/version 2 too-big 3 length-mismatch 4 bad-node 5 bad-regs-len
 *              6 no-table 7 stack-overflow 8 bad-opcode
 */
#include <avr/io.h>
#include <stdint.h>
#include <string.h>

#define BAUD_UBRR 25            /* 16 MHz / (16 * 38400) - 1 = 25.04 -> 0.16% error */
#define TBL_MAX   640           /* covers every certified table incl. wazuh_triage (302 B) */
#define REGS_MAX  (4 + 8 * 24)  /* node idx + 24 typed registers */
#define STACK_MAX 64

enum { TY_NONE = 0, TY_BOOL = 1, TY_INT = 2, TY_STR = 3 };
enum { OP_EQ = 0, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE, OP_TRUTHY };

static uint8_t tbl[TBL_MAX];
static uint8_t regs[REGS_MAX];
static uint16_t n_fields, n_atoms, n_nodes, n_edges, prog_len;
static uint16_t atoms_off, nodes_off, edges_off, prog_off_base;
static uint8_t loaded = 0;

/* ---------------------------------------------------------------- uart */
static void uart_init(void) {
    UBRR0 = BAUD_UBRR;
    UCSR0B = _BV(TXEN0) | _BV(RXEN0);
    UCSR0C = _BV(UCSZ01) | _BV(UCSZ00);
}
static uint8_t uart_getc(void) {
    while (!(UCSR0A & _BV(RXC0))) {}
    return UDR0;
}
static void uart_putc(uint8_t c) {
    while (!(UCSR0A & _BV(UDRE0))) {}
    UDR0 = c;
}
static uint16_t get_u16(void) {
    uint16_t lo = uart_getc();
    return lo | ((uint16_t)uart_getc() << 8);
}

/* ------------------------------------------------------- buffer readers */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | ((uint16_t)p[1] << 8)); }
static int32_t rd32(const uint8_t *p) {
    int32_t v;
    memcpy(&v, p, 4);           /* AVR is little-endian, same as the format */
    return v;
}

/* --------------------------------------------------------- table load */
static uint8_t parse_table(uint16_t len) {
    if (len < 28) return 3;
    if (rd32(tbl) != (int32_t)0x4D545050L || rd16(tbl + 4) != 1) return 1;
    n_fields = rd16(tbl + 6);
    n_atoms  = rd16(tbl + 10);
    n_nodes  = rd16(tbl + 12);
    n_edges  = rd16(tbl + 14);
    prog_len = rd16(tbl + 16);
    atoms_off = 28;
    nodes_off = atoms_off + 8 * n_atoms;
    edges_off = nodes_off + 4 * n_nodes;
    prog_off_base = edges_off + 6 * n_edges;
    uint16_t need = prog_off_base + 2 * prog_len;
    if (need != len) return 3;
    return 0;
}

/* ------------------------------------------- the evaluator core (interp.c, byte-exact) */
static uint8_t eval_atom(uint16_t atom_idx) {
    const uint8_t *a = tbl + atoms_off + 8 * (uint32_t)atom_idx;
    uint16_t field = rd16(a);
    uint8_t op = a[2], aty = a[3];
    int32_t aval = rd32(a + 4);
    const uint8_t *r = regs + 4 + 8 * (uint32_t)field;
    int32_t rty = rd32(r), rval = rd32(r + 4);
    uint8_t lnum = (rty == TY_BOOL || rty == TY_INT);
    uint8_t rnum = (aty == TY_BOOL || aty == TY_INT);
    switch (op) {
    case OP_EQ: case OP_NE: {
        uint8_t eq;
        if (lnum && rnum)                          eq = (rval == aval);
        else if (rty == TY_STR && aty == TY_STR)   eq = (rval == aval);
        else if (rty == TY_NONE && aty == TY_NONE) eq = 1;
        else                                       eq = 0;
        return op == OP_EQ ? eq : (uint8_t)!eq;
    }
    case OP_LT: case OP_LE: case OP_GT: case OP_GE:
        if (!(lnum && rnum)) return 0;             /* totality: non-numeric -> unsatisfied */
        switch (op) {
        case OP_LT: return rval <  aval;
        case OP_LE: return rval <= aval;
        case OP_GT: return rval >  aval;
        default:    return rval >= aval;
        }
    case OP_TRUTHY:
        return rty == TY_NONE ? 0 : (rval != 0);
    }
    return 0;
}

static int8_t eval_prog(uint16_t e_prog_off, uint16_t e_prog_cnt, uint8_t *err) {
    uint8_t stack[STACK_MAX];
    int8_t sp = 0;
    for (uint16_t i = 0; i < e_prog_cnt; i++) {
        uint16_t w = rd16(tbl + prog_off_base + 2 * (uint32_t)(e_prog_off + i));
        if (w < 0x8000) {
            if (sp >= STACK_MAX) { *err = 7; return 0; }
            stack[sp++] = eval_atom(w);
        } else switch (w) {
        case 0x8000: stack[sp - 1] = (uint8_t)!stack[sp - 1]; break;             /* NOT */
        case 0x8001: sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] && stack[sp]); break;
        case 0x8002: sp--; stack[sp - 1] = (uint8_t)(stack[sp - 1] || stack[sp]); break;
        case 0x8003: if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 1; break;
        case 0x8004: if (sp >= STACK_MAX) { *err = 7; return 0; } stack[sp++] = 0; break;
        default: *err = 8; return 0;
        }
    }
    return (int8_t)stack[0];
}

/* evaluate(node) -> matching edge index, or -1 (the priority encoder) */
static int8_t evaluate(uint16_t node, uint16_t *out_target, uint8_t *err) {
    const uint8_t *n = tbl + nodes_off + 4 * (uint32_t)node;
    uint16_t edge_off = rd16(n), edge_cnt = rd16(n + 2);
    for (uint16_t i = 0; i < edge_cnt; i++) {
        const uint8_t *e = tbl + edges_off + 6 * (uint32_t)(edge_off + i);
        if (eval_prog(rd16(e + 2), rd16(e + 4), err)) {
            *out_target = rd16(e);
            return (int8_t)i;
        }
        if (*err) return -1;
    }
    return -1;
}

/* ---------------------------------------------------------------- main loop */
static const char IDENT[] = "ppt-uno/1 atmega328p PPTM-v1";

int main(void) {
    uart_init();
    DDRB |= _BV(PB5);
    for (;;) {
        uint8_t cmd = uart_getc();
        if (cmd == 'I') {
            uart_putc('i');
            uart_putc((uint8_t)(sizeof(IDENT) - 1));
            for (uint8_t i = 0; i < sizeof(IDENT) - 1; i++) uart_putc(IDENT[i]);
        } else if (cmd == 'L') {
            uint16_t len = get_u16();
            if (len > TBL_MAX) {                     /* drain, then refuse */
                for (uint16_t i = 0; i < len; i++) (void)uart_getc();
                uart_putc('E'); uart_putc(2);
                continue;
            }
            for (uint16_t i = 0; i < len; i++) tbl[i] = uart_getc();
            uint8_t rc = parse_table(len);
            loaded = (rc == 0);
            if (rc) { uart_putc('E'); uart_putc(rc); }
            else    { uart_putc('l'); PORTB ^= _BV(PB5); }
        } else if (cmd == 'V') {
            uint16_t len = get_u16();
            if (len > REGS_MAX) {
                for (uint16_t i = 0; i < len; i++) (void)uart_getc();
                uart_putc('E'); uart_putc(5);
                continue;
            }
            for (uint16_t i = 0; i < len; i++) regs[i] = uart_getc();
            if (!loaded) { uart_putc('E'); uart_putc(6); continue; }
            if (len != 4 + 8 * (uint32_t)n_fields) { uart_putc('E'); uart_putc(5); continue; }
            uint16_t node = (uint16_t)rd32(regs);
            if (node >= n_nodes) { uart_putc('E'); uart_putc(4); continue; }
            uint8_t err = 0;
            uint16_t target = 0;
            int8_t e = evaluate(node, &target, &err);
            if (err)        { uart_putc('E'); uart_putc(err); }
            else if (e < 0) { uart_putc('N'); }
            else {
                uart_putc('M');
                uart_putc((uint8_t)e);
                uart_putc((uint8_t)(target & 0xFF));
                uart_putc((uint8_t)(target >> 8));
            }
        }
        /* unknown bytes are ignored: the host owns framing */
    }
}
