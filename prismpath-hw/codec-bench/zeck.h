// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
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
static inline uint64_t fib_at(uint8_t fib_index);
static inline uint16_t rd16(const uint16_t *source) { return pgm_read_word(source); }
static inline uint8_t rd8(const uint8_t *source) { return pgm_read_byte(source); }
#else
#define TBL
static inline uint64_t fib_at(uint8_t fib_index);
static inline uint16_t rd16(const uint16_t *source) { return *source; }
static inline uint8_t rd8(const uint8_t *source) { return *source; }
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
static inline uint64_t fib_at(uint8_t fib_index) { uint64_t value; memcpy_P(&value, &FIBS[fib_index], 8); return value; }
#else
static inline uint64_t fib_at(uint8_t fib_index) { return FIBS[fib_index]; }
#endif

typedef struct { uint8_t *buf; uint16_t bitpos; } bitacc_t;

static inline void put_bit(bitacc_t *acc, uint8_t bit) {
    if (bit) acc->buf[acc->bitpos >> 3] |= (uint8_t)(0x80u >> (acc->bitpos & 7u));
    acc->bitpos++;
}

/* Append the Fibonacci code of wire int value (>= 1). Returns 0, or -1 for value == 0 (invalid). */
static int8_t zeck_encode(bitacc_t *acc, uint64_t value) {
    if (value == 0) return -1;
    uint8_t top_index = 0;
    while (top_index + 1u < 78u && fib_at((uint8_t)(top_index + 1u)) <= value) top_index++;
    uint8_t code[80];
    memset(code, 0, (size_t)top_index + 1u);
    for (int8_t code_index = (int8_t)top_index; code_index >= 0; code_index--) {
        uint64_t fib_value = fib_at((uint8_t)code_index);
        if (fib_value <= value) { code[code_index] = 1; value -= fib_value; }
    }
    for (uint8_t code_index = 0; code_index <= top_index; code_index++) put_bit(acc, code[code_index]);
    put_bit(acc, 1);
    return 0;
}

/* One event: encode 4 wire ints into buf (pre zeroed). Returns byte length. */
static uint8_t encode_event(const uint16_t *syms, uint8_t *buf, uint8_t buflen) {
    memset(buf, 0, buflen);
    bitacc_t acc = { buf, 0 };
    for (uint8_t field_index = 0; field_index < 4; field_index++) (void)zeck_encode(&acc, rd16(&syms[field_index]));
    return (uint8_t)((acc.bitpos + 7u) >> 3);
}
