// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* blink_id.c — identify one physical board: blink the onboard LED (GPIO2) fast and forever.
 * Flashed to /dev/ttyUSB0 only, so the board that blinks is node A — the one with the dead sensor. */
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include <stdio.h>

#define LED_GPIO 2

void app_main(void) {
    gpio_reset_pin(LED_GPIO);
    gpio_set_direction(LED_GPIO, GPIO_MODE_OUTPUT);
    printf("\n[identify] THIS board is node A (/dev/ttyUSB0) — the failing sensor. LED on GPIO2 blinking.\n");
    while (1) {
        gpio_set_level(LED_GPIO, 1); vTaskDelay(pdMS_TO_TICKS(120));
        gpio_set_level(LED_GPIO, 0); vTaskDelay(pdMS_TO_TICKS(120));
    }
}
