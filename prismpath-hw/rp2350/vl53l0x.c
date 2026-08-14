/* vl53l0x.c — compact VL53L0X driver for the Pico SDK, ported from the Pololu VL53L0X library
 * (init + single-shot ranging). Register addresses and the init/tuning sequence follow that
 * implementation and the ST API it derives from. */
#include "vl53l0x.h"
#include "pico/stdlib.h"
#include <string.h>

/* register addresses used */
#define SYSRANGE_START                              0x00
#define SYSTEM_SEQUENCE_CONFIG                       0x01
#define SYSTEM_INTERRUPT_CONFIG_GPIO                 0x0A
#define SYSTEM_INTERRUPT_CLEAR                       0x0B
#define RESULT_INTERRUPT_STATUS                      0x13
#define RESULT_RANGE_STATUS                          0x14
#define MSRC_CONFIG_CONTROL                          0x60
#define FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT  0x44
#define GPIO_HV_MUX_ACTIVE_HIGH                      0x84
#define DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD          0x4E
#define DYNAMIC_SPAD_REF_EN_START_OFFSET             0x4F
#define GLOBAL_CONFIG_SPAD_ENABLES_REF_0             0xB0
#define GLOBAL_CONFIG_REF_EN_START_SELECT            0xB6
#define VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV            0x89

/* ---------------------------------------------------------------- I2C helpers */
static void wr8(vl53l0x_t *s, uint8_t reg, uint8_t val) {
    uint8_t b[2] = {reg, val};
    i2c_write_blocking(s->i2c, s->addr, b, 2, false);
}
static uint8_t rd8(vl53l0x_t *s, uint8_t reg) {
    uint8_t v = 0;
    i2c_write_blocking(s->i2c, s->addr, &reg, 1, true);
    i2c_read_blocking(s->i2c, s->addr, &v, 1, false);
    return v;
}
static void wr16(vl53l0x_t *s, uint8_t reg, uint16_t val) {
    uint8_t b[3] = {reg, (uint8_t)(val >> 8), (uint8_t)(val & 0xFF)};
    i2c_write_blocking(s->i2c, s->addr, b, 3, false);
}
static uint16_t rd16(vl53l0x_t *s, uint8_t reg) {
    uint8_t v[2] = {0, 0};
    i2c_write_blocking(s->i2c, s->addr, &reg, 1, true);
    i2c_read_blocking(s->i2c, s->addr, v, 2, false);
    return ((uint16_t)v[0] << 8) | v[1];
}
static void wr_multi(vl53l0x_t *s, uint8_t reg, const uint8_t *src, uint8_t n) {
    uint8_t b[16];
    b[0] = reg;
    memcpy(b + 1, src, n);
    i2c_write_blocking(s->i2c, s->addr, b, n + 1, false);
}
static void rd_multi(vl53l0x_t *s, uint8_t reg, uint8_t *dst, uint8_t n) {
    i2c_write_blocking(s->i2c, s->addr, &reg, 1, true);
    i2c_read_blocking(s->i2c, s->addr, dst, n, false);
}

/* ---------------------------------------------------------------- timeout */
static absolute_time_t s_deadline;
static void start_timeout(vl53l0x_t *s) { s_deadline = make_timeout_time_ms(s->io_timeout_ms); }
static bool timed_out(void) { return absolute_time_diff_us(get_absolute_time(), s_deadline) < 0; }

/* ---------------------------------------------------------------- SPAD info */
static bool get_spad_info(vl53l0x_t *s, uint8_t *count, bool *type_is_aperture) {
    wr8(s, 0x80, 0x01);
    wr8(s, 0xFF, 0x01);
    wr8(s, 0x00, 0x00);
    wr8(s, 0xFF, 0x06);
    wr8(s, 0x83, rd8(s, 0x83) | 0x04);
    wr8(s, 0xFF, 0x07);
    wr8(s, 0x81, 0x01);
    wr8(s, 0x80, 0x01);
    wr8(s, 0x94, 0x6b);
    wr8(s, 0x83, 0x00);
    start_timeout(s);
    while (rd8(s, 0x83) == 0x00) { if (timed_out()) return false; }
    wr8(s, 0x83, 0x01);
    uint8_t tmp = rd8(s, 0x92);
    *count = tmp & 0x7f;
    *type_is_aperture = (tmp >> 7) & 0x01;
    wr8(s, 0x81, 0x00);
    wr8(s, 0xFF, 0x06);
    wr8(s, 0x83, rd8(s, 0x83) & ~0x04);
    wr8(s, 0xFF, 0x01);
    wr8(s, 0x00, 0x01);
    wr8(s, 0xFF, 0x00);
    wr8(s, 0x80, 0x00);
    return true;
}

static bool ref_calibration(vl53l0x_t *s, uint8_t vhv_init_byte) {
    wr8(s, SYSRANGE_START, 0x01 | vhv_init_byte);
    start_timeout(s);
    while ((rd8(s, RESULT_INTERRUPT_STATUS) & 0x07) == 0) { if (timed_out()) return false; }
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);
    wr8(s, SYSRANGE_START, 0x00);
    return true;
}

/* ---------------------------------------------------------------- init */
bool vl53l0x_init(vl53l0x_t *s, i2c_inst_t *i2c, uint8_t addr) {
    s->i2c = i2c;
    s->addr = addr;
    s->io_timeout_ms = 500;
    s->did_timeout = false;

    /* sanity: model id register 0xC0 should read 0xEE */
    if (rd8(s, 0xC0) != 0xEE) return false;

    /* DataInit: 2V8 mode + I2C standard mode */
    wr8(s, VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV, rd8(s, VHV_CONFIG_PAD_SCL_SDA__EXTSUP_HV) | 0x01);
    wr8(s, 0x88, 0x00);
    wr8(s, 0x80, 0x01);
    wr8(s, 0xFF, 0x01);
    wr8(s, 0x00, 0x00);
    s->stop_variable = rd8(s, 0x91);
    wr8(s, 0x00, 0x01);
    wr8(s, 0xFF, 0x00);
    wr8(s, 0x80, 0x00);
    wr8(s, MSRC_CONFIG_CONTROL, rd8(s, MSRC_CONFIG_CONTROL) | 0x12);
    wr16(s, FINAL_RANGE_CONFIG_MIN_COUNT_RATE_RTN_LIMIT, (uint16_t)(0.25 * (1 << 7)));  /* 0.25 MCPS */
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0xFF);

    /* StaticInit: reference SPADs */
    uint8_t spad_count;
    bool spad_type_is_aperture;
    if (!get_spad_info(s, &spad_count, &spad_type_is_aperture)) return false;
    uint8_t ref_spad_map[6];
    rd_multi(s, GLOBAL_CONFIG_SPAD_ENABLES_REF_0, ref_spad_map, 6);
    wr8(s, 0xFF, 0x01);
    wr8(s, DYNAMIC_SPAD_REF_EN_START_OFFSET, 0x00);
    wr8(s, DYNAMIC_SPAD_NUM_REQUESTED_REF_SPAD, 0x2C);
    wr8(s, 0xFF, 0x00);
    wr8(s, GLOBAL_CONFIG_REF_EN_START_SELECT, 0xB4);
    uint8_t first_spad = spad_type_is_aperture ? 12 : 0;
    uint8_t enabled = 0;
    for (uint8_t i = 0; i < 48; i++) {
        if (i < first_spad || enabled == spad_count) {
            ref_spad_map[i / 8] &= ~(1 << (i % 8));
        } else if ((ref_spad_map[i / 8] >> (i % 8)) & 0x1) {
            enabled++;
        }
    }
    wr_multi(s, GLOBAL_CONFIG_SPAD_ENABLES_REF_0, ref_spad_map, 6);

    /* load tuning settings (ST default) */
    static const uint8_t tuning[] = {
        0xFF,0x01, 0x00,0x00, 0xFF,0x00, 0x09,0x00, 0x10,0x00, 0x11,0x00, 0x24,0x01, 0x25,0xFF,
        0x75,0x00, 0xFF,0x01, 0x4E,0x2C, 0x48,0x00, 0x30,0x20, 0xFF,0x00, 0x30,0x09, 0x54,0x00,
        0x31,0x04, 0x32,0x03, 0x40,0x83, 0x46,0x25, 0x60,0x00, 0x27,0x00, 0x50,0x06, 0x51,0x00,
        0x52,0x96, 0x56,0x08, 0x57,0x30, 0x61,0x00, 0x62,0x00, 0x64,0x00, 0x65,0x00, 0x66,0xA0,
        0xFF,0x01, 0x22,0x32, 0x47,0x14, 0x49,0xFF, 0x4A,0x00, 0xFF,0x00, 0x7A,0x0A, 0x7B,0x00,
        0x78,0x21, 0xFF,0x01, 0x23,0x34, 0x42,0x00, 0x44,0xFF, 0x45,0x26, 0x46,0x05, 0x40,0x40,
        0x0E,0x06, 0x20,0x1A, 0x43,0x40, 0xFF,0x00, 0x34,0x03, 0x35,0x44, 0xFF,0x01, 0x31,0x04,
        0x4B,0x09, 0x4C,0x05, 0x4D,0x04, 0xFF,0x00, 0x44,0x00, 0x45,0x20, 0x47,0x08, 0x48,0x28,
        0x67,0x00, 0x70,0x04, 0x71,0x01, 0x72,0xFE, 0x76,0x00, 0x77,0x00, 0xFF,0x01, 0x0D,0x01,
        0xFF,0x00, 0x80,0x01, 0x01,0xF8, 0xFF,0x01, 0x8E,0x01, 0x00,0x01, 0xFF,0x00, 0x80,0x00,
    };
    for (size_t i = 0; i < sizeof(tuning); i += 2) wr8(s, tuning[i], tuning[i + 1]);

    /* interrupt config: new-sample-ready, active low */
    wr8(s, SYSTEM_INTERRUPT_CONFIG_GPIO, 0x04);
    wr8(s, GPIO_HV_MUX_ACTIVE_HIGH, rd8(s, GPIO_HV_MUX_ACTIVE_HIGH) & ~0x10);
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);

    /* ref calibration (VHV then phase) */
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0x01);
    if (!ref_calibration(s, 0x40)) return false;
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0x02);
    if (!ref_calibration(s, 0x00)) return false;
    wr8(s, SYSTEM_SEQUENCE_CONFIG, 0xE8);   /* restore ranging sequence steps */
    return true;
}

/* ---------------------------------------------------------------- single-shot range (mm) */
uint16_t vl53l0x_read_range_single(vl53l0x_t *s) {
    wr8(s, 0x80, 0x01);
    wr8(s, 0xFF, 0x01);
    wr8(s, 0x00, 0x00);
    wr8(s, 0x91, s->stop_variable);
    wr8(s, 0x00, 0x01);
    wr8(s, 0xFF, 0x00);
    wr8(s, 0x80, 0x00);
    wr8(s, SYSRANGE_START, 0x01);
    start_timeout(s);
    while (rd8(s, SYSRANGE_START) & 0x01) { if (timed_out()) { s->did_timeout = true; return 65535; } }
    start_timeout(s);
    while ((rd8(s, RESULT_INTERRUPT_STATUS) & 0x07) == 0) {
        if (timed_out()) { s->did_timeout = true; return 65535; }
    }
    uint16_t range = rd16(s, RESULT_RANGE_STATUS + 10);   /* 0x1E */
    wr8(s, SYSTEM_INTERRUPT_CLEAR, 0x01);
    return range;
}
