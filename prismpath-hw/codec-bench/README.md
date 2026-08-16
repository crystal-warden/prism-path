# codec-bench: the wire encoder on bare metal

The front half of Phase C2: a portable C Zeckendorf encoder (`zeck.h`, bit exact with the Python
reference; 78 entry u64 Fibonacci table covering the 2^53 domain, 624 bytes of constant data) plus
a verify-then-time harness (`bench_core.h`). `gen_bench_data.py` generates the corpus AND its
expected wire bytes with the reference implementation; each target proves byte identity on device
before any timing, so the published number is the cost of a verified codec. Targets: `avr_bench.c`
(Uno R3, `make` style build below), `esp32/` (ESP-IDF), `rp2350/` (both ISAs from one source).
Results: `results.md`. The FPGA shift register codec remains the unbuilt half of C2.

```
python3 gen_bench_data.py
avr-gcc -mmcu=atmega328p -DF_CPU=16000000UL -Os -o avr_bench.elf avr_bench.c && avr-objcopy -O ihex avr_bench.elf avr_bench.hex
```
