/* Codec bench on the ATmega328P (Arduino Uno R3, 16 MHz): verify the Zeckendorf wire encoder
 * byte for byte against the reference corpus, then time it. Timer1 /1024 (64 us tick, one
 * overflow tolerated per window); UART 38400 8N1, the harness baud the cert rig already uses. */
#include <avr/io.h>
#include <stdio.h>
#include <util/delay.h>

static int uart_putc(char c, FILE *f) {
    (void)f;
    if (c == '\n') uart_putc('\r', 0);
    while (!(UCSR0A & (1 << UDRE0))) {}
    UDR0 = (uint8_t)c;
    return 0;
}
static FILE uart_out = FDEV_SETUP_STREAM(uart_putc, NULL, _FDEV_SETUP_WRITE);
#define bench_printf printf

static void time_reset(void) { TCNT1 = 0; TIFR1 = (1 << TOV1); }
static uint32_t now_us(void) {
    uint32_t t = TCNT1;
    if (TIFR1 & (1 << TOV1)) t += 65536UL;
    return t * 64u;
}

#include "bench_core.h"

int main(void) {
    UBRR0 = 25;                       /* 38400 @ 16 MHz, 0.16% error */
    UCSR0B = (1 << TXEN0);
    UCSR0C = (1 << UCSZ01) | (1 << UCSZ00);
    stdout = &uart_out;
    TCCR1A = 0;
    TCCR1B = (1 << CS12) | (1 << CS10);   /* /1024 */
    _delay_ms(500);
    for (;;) {
        bench_printf("AVR atmega328p 16MHz codec-bench\n");
        RUN_WORKLOAD("TYP", TYP, TYP_MAXWIRE);
        RUN_WORKLOAD("STRESS", STRESS, STRESS_MAXWIRE);
        _delay_ms(4000);
    }
}
