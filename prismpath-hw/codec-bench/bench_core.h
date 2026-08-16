/* Verify then time. Any byte mismatch vs the reference generated corpus halts before timing:
 * the published number is the cost of a VERIFIED codec. now_us/print supplied per target. */
#pragma once
#include "zeck.h"
#include "bench_data.h"

#ifdef __AVR__
#define GET_ROW(W, r) (&W##_SYMS[r][0])
#define REPS 32u
#else
#define GET_ROW(W, r) (&W##_SYMS[r][0])
#define REPS 1024u
#endif

#define RUN_WORKLOAD(NAME, W, MAXW)                                                     \
  do {                                                                                  \
    uint8_t buf[16];                                                                    \
    uint32_t bad = 0;                                                                   \
    for (uint8_t r = 0; r < BENCH_N; r++) {                                             \
      uint8_t len = encode_event(GET_ROW(W, r), buf, sizeof buf);                       \
      if (len != rd8(&W##_WLEN[r])) { bad = 1000u + r; break; }                         \
      for (uint8_t i = 0; i < len; i++)                                                 \
        if (buf[i] != rd8(&W##_WIRE[r][i])) { bad = 2000u + r; goto done_##W; }         \
    }                                                                                   \
    done_##W:                                                                           \
    if (bad) { bench_printf("%s VERIFY FAIL %lu\n", NAME, (unsigned long)bad); break; } \
    volatile uint8_t sink = 0;                                                          \
    uint32_t events = (uint32_t)REPS * BENCH_N;                                         \
    time_reset();                                                                       \
    uint32_t t0 = now_us();                                                             \
    for (uint16_t rep = 0; rep < REPS; rep++)                                           \
      for (uint8_t r = 0; r < BENCH_N; r++)                                             \
        sink ^= encode_event(GET_ROW(W, r), buf, sizeof buf);                           \
    uint32_t dt = now_us() - t0;                                                        \
    (void)sink;                                                                         \
    bench_printf("%s events=%lu total_us=%lu ns_per_event=%lu\n", NAME,                 \
                 (unsigned long)events, (unsigned long)dt,                              \
                 (unsigned long)(((uint64_t)dt * 1000u) / events));                     \
  } while (0)
