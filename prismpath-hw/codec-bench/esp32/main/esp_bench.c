// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* Codec bench on the ESP32 (Xtensa LX6, 240 MHz): verify then time, same core as every ISA. */
#include <stdio.h>
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define bench_printf printf
static void time_reset(void) {}
static uint32_t now_us(void) { return (uint32_t)esp_timer_get_time(); }

#include "bench_core.h"

void app_main(void) {
    vTaskDelay(pdMS_TO_TICKS(500));
    for (;;) {
        bench_printf("ESP32 xtensa-lx6 240MHz codec-bench\n");
        RUN_WORKLOAD("TYP", TYP, TYP_MAXWIRE);
        RUN_WORKLOAD("STRESS", STRESS, STRESS_MAXWIRE);
        vTaskDelay(pdMS_TO_TICKS(4000));
    }
}
