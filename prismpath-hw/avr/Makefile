# ppt_uno — the PPT v1 interpreter on an ATmega328P (Arduino Uno R3).
#   make            build ppt_uno.hex
#   make flash      flash over optiboot (PORT=/dev/ttyACM1 by default; may need sudo)
#   make cert       certify against the frozen predicate corpus over serial
#   make dist       build ppt_uno_dist.hex, the constrained enforcement point (B12), and print its sizes. This
#                   is a build time estimate of flash and static RAM, not a measurement on the board
#   make anchor     write uno_anchor.eep, the EEPROM anchor the dist image is provisioned with (uno_anchor.py)

PORT ?= /dev/ttyACM1
MCU   = atmega328p
F_CPU = 16000000UL

all: ppt_uno.hex

DIST = ../dist
MONO = ../mesh/main
DIST_SRC = ppt_uno_dist.c $(DIST)/pp_dist.c $(MONO)/monocypher.c $(MONO)/monocypher-ed25519.c
DIST_FLAGS = -mmcu=$(MCU) -DF_CPU=$(F_CPU) -DPP_DIST_PROFILE_MIN -std=gnu11 -Os -Wall -Wextra \
             -ffunction-sections -fdata-sections -fstack-usage -I$(DIST) -I$(MONO)

ppt_uno.elf: ppt_uno.c
	avr-gcc -mmcu=$(MCU) -DF_CPU=$(F_CPU) -Os -Wall -Wextra -o $@ $<
	avr-size $@

ppt_uno.hex: ppt_uno.elf
	avr-objcopy -O ihex $< $@

dist: ppt_uno_dist.hex

ppt_uno_dist.elf: $(DIST_SRC) $(DIST)/pp_dist.h $(DIST)/pp_link.h
	avr-gcc $(DIST_FLAGS) -Wl,--gc-sections,--noinhibit-exec -o $@ $(DIST_SRC)
	avr-size -C --mcu=$(MCU) $@

ppt_uno_dist.hex: ppt_uno_dist.elf
	avr-objcopy -O ihex -R .eeprom $< $@

anchor:
	python3 uno_anchor.py

flash: ppt_uno.hex
	avrdude -q -c arduino -p m328p -P $(PORT) -b 115200 -U flash:w:$<:i

cert:
	python3 certify_uno.py --port $(PORT)

clean:
	rm -f ppt_uno.elf ppt_uno.hex ppt_uno_dist.elf ppt_uno_dist.hex *.su

.PHONY: all dist anchor flash cert clean
