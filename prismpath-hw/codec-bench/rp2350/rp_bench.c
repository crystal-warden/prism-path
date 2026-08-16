/* Codec bench on the RP2350: one source, both ISAs (Cortex-M33 arm-s / Hazard3 riscv). */
#include <stdio.h>
#include "pico/stdlib.h"

#define bench_printf printf
static void time_reset(void) {}
static uint32_t now_us(void) { return (uint32_t)time_us_64(); }

#include "bench_core.h"

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    for (;;) {
#if defined(__riscv)
        bench_printf("RP2350 hazard3-riscv 150MHz codec-bench\n");
#else
        bench_printf("RP2350 cortex-m33 150MHz codec-bench\n");
#endif
        RUN_WORKLOAD("TYP", TYP, TYP_MAXWIRE);
        RUN_WORKLOAD("STRESS", STRESS, STRESS_MAXWIRE);
        sleep_ms(4000);
    }
}
