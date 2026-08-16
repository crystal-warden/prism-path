# Codec bench: the C Zeckendorf encoder on four MCU ISAs (2026-08-16)

Every number is from a codec verified byte for byte on device against reference generated wire
bytes before timing. Workloads: typical = 64 four field events, wire ints 1..6 (2.281 B/event);
stress = a 1,000 cell codebook, wire ints 1..1001 (7.062 B/event).

| ISA (board) | clock | typical ns/event | stress ns/event | approx cycles (typ) |
|---|---|---|---|---|
| ATmega328P, 8-bit AVR (Uno R3) | 16 MHz | 462,718 | 1,756,625 | ~7,400 |
| Xtensa LX6 (ESP32) | 240 MHz | 9,283 | 27,902 | ~2,230 |
| Cortex-M33 (RP2350) | 150 MHz | 5,338 | 14,870 | ~800 |
| Hazard3 RISC-V (RP2350) | 150 MHz | 4,645 | 13,690 | ~700 |

Raw lines:
AVR: TYP events=2048 total_us=947648 ns_per_event=462718 / STRESS events=2048 total_us=3597568 ns_per_event=1756625
ESP32: TYP events=65536 total_us=608377 ns_per_event=9283 / STRESS events=65536 total_us=1828647 ns_per_event=27902
M33: TYP events=65536 total_us=349850 ns_per_event=5338 / STRESS events=65536 total_us=974556 ns_per_event=14870
Hazard3: TYP events=65536 total_us=304463 ns_per_event=4645 / STRESS events=65536 total_us=897226 ns_per_event=13690
