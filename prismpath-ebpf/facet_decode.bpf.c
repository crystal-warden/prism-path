// facet_decode.bpf.c — the kernel decode plane: XDP decode-and-rewrite for the Facet DATAGRAM
// profile. A UDP datagram to FACET_PORT carrying one byte-aligned Facet frame is decoded
// (self-delimiting Zeckendorf, policy independent) and its payload REWRITTEN in place to
//   [ 'F' ][ u8 count ][ u16le wire_int * count ]
// so an ordinary UDP socket application receives decoded cell values and never knows Facet
// existed. Strict contract in kernel: any malformed frame is XDP_DROP (counted, never silent,
// never a wrong event). Non-Facet traffic passes untouched.
//
// The per-byte decode runs under bpf_loop (kernel 5.17+, the documented floor): the verifier
// checks the callback ONCE rather than exploring a fully-unrolled branchy FSM, which keeps the
// program small regardless of frame size.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define FACET_PORT 4711
/* MAX_SYMS=16 fields per frame; MAX_PAYLOAD=32 bytes (generous: typical frames are 2 to 7).
   Fibonacci values are advanced incrementally (fa, fb) rather than looked up from a table: a
   .rodata array does not resolve reliably when read inside a bpf_loop callback subprogram. */
#define MAX_PAYLOAD 32
#define MAX_SYMS 16

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 4);
         __type(key, __u32); __type(value, __u64); } facet_stats SEC(".maps");

static __always_inline void bump(__u32 k) {
    __u64 *v = bpf_map_lookup_elem(&facet_stats, &k);
    if (v) __sync_fetch_and_add(v, 1);
}

struct decode_ctx {
    __u32 plen;
    __u32 n;
    __u32 val;
    __u32 fa;       /* current Fibonacci value for this bit position (F2, F3, ...) */
    __u32 fb;       /* next Fibonacci value */
    __u8  prev;
    __u8  bad;
    __u8  buf[MAX_PAYLOAD];
    __u16 out[MAX_SYMS];
};

/* One bit per call, reading only the stack buffer, advancing (fa, fb) incrementally so no
   .rodata table is touched. bpf_loop verifies this once regardless of frame length. */
static long bit_cb(__u32 bi, void *vctx) {
    struct decode_ctx *c = vctx;
    __u32 byi = bi >> 3;
    if (byi >= c->plen) return 1;                       /* done */
    __u8 byte = c->buf[byi & (MAX_PAYLOAD - 1)];
    __u8 bit = (byte >> (7 - (bi & 7))) & 1;
    if (bit && c->prev) {                               /* terminator: codeword complete */
        if (c->n >= MAX_SYMS || c->val == 0 || c->val > 0xFFFF) { c->bad = 1; return 1; }
        c->out[c->n & (MAX_SYMS - 1)] = (__u16)c->val;
        c->n++; c->val = 0; c->fa = 1; c->fb = 2; c->prev = 0;
    } else {
        if (bit) {
            if (c->val > 0xFFFF) { c->bad = 1; return 1; }
            c->val += c->fa;
        }
        __u32 next = c->fa + c->fb;                     /* advance the Fibonacci pair */
        c->fa = c->fb; c->fb = next;
        c->prev = bit;
    }
    return 0;
}

SEC("xdp")
int facet_decode(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *end  = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > end) return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_PASS;
    if (ip->ihl != 5 || ip->protocol != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > end) return XDP_PASS;
    if (udp->dest != bpf_htons(FACET_PORT)) { bump(3); return XDP_PASS; }

    __u8 *p = (void *)(udp + 1);
    __u16 udp_total = bpf_ntohs(udp->len);
    if (udp_total < 8) { bump(2); return XDP_DROP; }
    __u32 plen = udp_total - 8;
    if (plen == 0 || plen > MAX_PAYLOAD) { bump(2); return XDP_DROP; }

    /* Copy the payload off the packet into a stack buffer in one helper call, then decode purely
       over the stack buffer: a masked stack read does not fork the verifier's packet-bounds
       state the way a per-bit packet read does, so a single flat bit loop stays in budget while
       carrying the accumulator across byte boundaries without a callback. */
    struct decode_ctx c = { .plen = plen, .fa = 1, .fb = 2 };
    if (plen > MAX_PAYLOAD) { bump(2); return XDP_DROP; }   /* re-assert for the verifier */
    if (bpf_xdp_load_bytes(ctx, 42, c.buf, plen)) { bump(1); return XDP_DROP; }
    bpf_loop(MAX_PAYLOAD * 8, bit_cb, &c, 0);
    if (c.bad) { bump(1); return XDP_DROP; }
    if (c.val != 0) { bump(1); return XDP_DROP; }          /* nonzero tail = truncated codeword */
    if (c.n == 0) { bump(1); return XDP_DROP; }

    __u32 nn = c.n;
    __u32 new_plen = 2 + 2 * nn;
    int delta = (int)new_plen - (int)plen;
    if (bpf_xdp_adjust_tail(ctx, delta)) { bump(1); return XDP_DROP; }

    /* pointers invalidated: reparse */
    data = (void *)(long)ctx->data;
    end  = (void *)(long)ctx->data_end;
    eth = data;
    if ((void *)(eth + 1) > end) return XDP_DROP;
    ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > end) return XDP_DROP;
    udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > end) return XDP_DROP;
    p = (void *)(udp + 1);
    if (p + 2 > (__u8 *)end) return XDP_DROP;
    p[0] = 'F';
    p[1] = (__u8)nn;
    for (__u32 i = 0; i < MAX_SYMS; i++) {
        if (i >= nn) break;
        __u8 *q = p + 2 + 2 * i;
        if (q + 2 > (__u8 *)end) return XDP_DROP;
        __u16 v = c.out[i & (MAX_SYMS - 1)];
        q[0] = (__u8)(v & 0xFF);                         /* little endian */
        q[1] = (__u8)(v >> 8);
    }

    /* fix lengths + checksums */
    __u16 udp_len = 8 + new_plen;
    __u16 tot_len = 20 + udp_len;
    ip->tot_len = bpf_htons(tot_len);
    udp->len = bpf_htons(udp_len);
    udp->check = 0;                                      /* legal for IPv4 UDP */
    ip->check = 0;
    __u32 sum = 0;
    __u16 *w = (__u16 *)ip;
    if ((void *)(w + 10) > end) return XDP_DROP;
    for (int i = 0; i < 10; i++) sum += w[i];
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    ip->check = (__u16)~sum;

    bump(0);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
