/* vl53l0x.h — a compact VL53L0X time-of-flight driver for the Pico SDK (RP2350).
 *
 * A faithful port of the essential path of the well-known Pololu VL53L0X library (init + single-shot
 * ranging) onto the Pico SDK I2C API. Enough to read distance in millimetres; not the full ST API. */
#ifndef VL53L0X_H
#define VL53L0X_H

#include <stdint.h>
#include <stdbool.h>
#include "hardware/i2c.h"

#define VL53L0X_ADDR 0x29

typedef struct {
    i2c_inst_t *i2c;
    uint8_t addr;
    uint8_t stop_variable;
    uint16_t io_timeout_ms;
    bool did_timeout;
} vl53l0x_t;

/* Initialise the sensor on the given I2C bus. Returns true on success. */
bool vl53l0x_init(vl53l0x_t *s, i2c_inst_t *i2c, uint8_t addr);

/* One single-shot ranging measurement, blocking. Returns distance in mm; 65535 on timeout/out-of-range. */
uint16_t vl53l0x_read_range_single(vl53l0x_t *s);

#endif
