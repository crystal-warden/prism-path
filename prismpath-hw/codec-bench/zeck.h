/* Portable Zeckendorf (Fibonacci) wire encoder — the front half of Phase C2.
 * Bit-exact with the Python reference (zeckendorf.encode_stream -> packed.pack(bits, 8)):
 * each wire int n >= 1 emits bits for F2..Fk ascending then a terminator 1 (the self framing
 * "11"); bits fill bytes MSB first; the final byte is zero padded. The FIBS table F2..F79
 * (78 entries, 624 bytes) covers the full 2^53 range the wire's f64 domain allows. */
#pragma once
#include <stdint.h>
#include <string.h>
#ifdef __AVR__
#include <avr/pgmspace.h>
#define TBL PROGMEM
static inline uint64_t fib_at(uint8_t i);
static inline uint16_t rd16(const uint16_t *p) { return pgm_read_word(p); }
static inline uint8_t rd8(const uint8_t *p) { return pgm_read_byte(p); }
#else
#define TBL
static inline uint64_t fib_at(uint8_t i);
static inline uint16_t rd16(const uint16_t *p) { return *p; }
static inline uint8_t rd8(const uint8_t *p) { return *p; }
#endif

static const uint64_t TBL FIBS[78] = {
1ULL, 2ULL, 3ULL, 5ULL,
  8ULL, 13ULL, 21ULL, 34ULL,
  55ULL, 89ULL, 144ULL, 233ULL,
  377ULL, 610ULL, 987ULL, 1597ULL,
  2584ULL, 4181ULL, 6765ULL, 10946ULL,
  17711ULL, 28657ULL, 46368ULL, 75025ULL,
  121393ULL, 196418ULL, 317811ULL, 514229ULL,
  832040ULL, 1346269ULL, 2178309ULL, 3524578ULL,
  5702887ULL, 9227465ULL, 14930352ULL, 24157817ULL,
  39088169ULL, 63245986ULL, 102334155ULL, 165580141ULL,
  267914296ULL, 433494437ULL, 701408733ULL, 1134903170ULL,
  1836311903ULL, 2971215073ULL, 4807526976ULL, 7778742049ULL,
  12586269025ULL, 20365011074ULL, 32951280099ULL, 53316291173ULL,
  86267571272ULL, 139583862445ULL, 225851433717ULL, 365435296162ULL,
  591286729879ULL, 956722026041ULL, 1548008755920ULL, 2504730781961ULL,
  4052739537881ULL, 6557470319842ULL, 10610209857723ULL, 17167680177565ULL,
  27777890035288ULL, 44945570212853ULL, 72723460248141ULL, 117669030460994ULL,
  190392490709135ULL, 308061521170129ULL, 498454011879264ULL, 806515533049393ULL,
  1304969544928657ULL, 2111485077978050ULL, 3416454622906707ULL, 5527939700884757ULL,
  8944394323791464ULL, 14472334024676221ULL
};

#ifdef __AVR__
static inline uint64_t fib_at(uint8_t i) { uint64_t v; memcpy_P(&v, &FIBS[i], 8); return v; }
#else
static inline uint64_t fib_at(uint8_t i) { return FIBS[i]; }
#endif

typedef struct { uint8_t *buf; uint16_t bitpos; } bitacc_t;

static inline void put_bit(bitacc_t *a, uint8_t b) {
    if (b) a->buf[a->bitpos >> 3] |= (uint8_t)(0x80u >> (a->bitpos & 7u));
    a->bitpos++;
}

/* Append the Fibonacci code of wire int n (>= 1). Returns 0, or -1 for n == 0 (invalid). */
static int8_t zeck_encode(bitacc_t *a, uint64_t n) {
    if (n == 0) return -1;
    uint8_t k = 0;
    while (k + 1u < 78u && fib_at((uint8_t)(k + 1u)) <= n) k++;
    uint8_t code[80];
    memset(code, 0, (size_t)k + 1u);
    for (int8_t i = (int8_t)k; i >= 0; i--) {
        uint64_t f = fib_at((uint8_t)i);
        if (f <= n) { code[i] = 1; n -= f; }
    }
    for (uint8_t i = 0; i <= k; i++) put_bit(a, code[i]);
    put_bit(a, 1);
    return 0;
}

/* One event: encode BENCH_FIELDS wire ints into buf (pre zeroed). Returns byte length. */
static uint8_t encode_event(const uint16_t *syms, uint8_t *buf, uint8_t buflen) {
    memset(buf, 0, buflen);
    bitacc_t a = { buf, 0 };
    for (uint8_t f = 0; f < 4; f++) (void)zeck_encode(&a, rd16(&syms[f]));
    return (uint8_t)((a.bitpos + 7u) >> 3);
}
