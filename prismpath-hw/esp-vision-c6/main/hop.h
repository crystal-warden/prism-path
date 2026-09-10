// The 802.15.4 hop, shared by both XIAO ESP32C6 roles.
// Raw data frames, PAN 0x5050, short addresses, broadcast, channel 25 (2475 MHz, clear of Wi-Fi channel 1).
// One ESP-NOW payload (up to 250 bytes) becomes sub frames of at most SUB_DATA bytes:
//   'S' | id u16 | idx u8 | total u8 | data[]      reassembled on the host side into the original payload
#pragma once
#include <string.h>
#include <stdint.h>
#include "driver/gpio.h"
#include "esp_ieee802154.h"
#define HOP_CHANNEL 25
#define HOP_PANID 0x5050
#define MHR_LEN 9
#define SUB_HDR 5
#define SUB_DATA (127 - 2 - MHR_LEN - SUB_HDR)   // 111
// Seeed XIAO ESP32C6: the RF switch is enabled by GPIO3 low, and GPIO14 low selects the on board antenna.
static void xiao_antenna_internal(void)
{
#ifdef NO_ANT
    return;   // leave the RF switch pins as the board powers up
#endif
    gpio_config_t g = { .pin_bit_mask = (1ULL << 3) | (1ULL << 14), .mode = GPIO_MODE_OUTPUT }; gpio_config(&g);
#ifndef ANT3
#define ANT3 0
#endif
#ifndef ANT14
#define ANT14 0
#endif
    gpio_set_level(3, ANT3); gpio_set_level(14, ANT14);
}
// rx_idle false: a transmit only role leaves the 802.15.4 radio idle between bursts, so the Wi-Fi side keeps
// its airtime (with continuous 802.15.4 receive the access point could not even complete an association).
static void hop_radio_init(uint16_t short_addr, bool promiscuous, bool rx_idle)
{
    ESP_ERROR_CHECK(esp_ieee802154_enable());
    esp_ieee802154_set_channel(HOP_CHANNEL); esp_ieee802154_set_panid(HOP_PANID); esp_ieee802154_set_short_address(short_addr);
    esp_ieee802154_set_promiscuous(promiscuous); esp_ieee802154_set_rx_when_idle(rx_idle);
    if (rx_idle) esp_ieee802154_receive();
}
// Build a broadcast data frame around `data`; returns the buffer length written (frame[0] counts the FCS).
static uint8_t hop_build(uint8_t *frame, uint8_t seq, uint16_t src, const uint8_t *data, uint8_t n)
{
    uint8_t *m = frame + 1;
    m[0] = 0x41; m[1] = 0x88;                 // data frame, PAN ID compression, short dst and src, 2003
    m[2] = seq; m[3] = HOP_PANID & 0xff; m[4] = HOP_PANID >> 8; m[5] = 0xff; m[6] = 0xff; m[7] = src & 0xff; m[8] = src >> 8;
    memcpy(m + MHR_LEN, data, n);
    frame[0] = (uint8_t)(MHR_LEN + n + 2);
    return (uint8_t)(1 + MHR_LEN + n);
}
