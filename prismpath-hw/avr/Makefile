# ppt_uno — the PPT v1 interpreter on an ATmega328P (Arduino Uno R3).
#   make            build ppt_uno.hex
#   make flash      flash over optiboot (PORT=/dev/ttyACM1 by default; may need sudo)
#   make cert       certify against the frozen predicate corpus over serial

PORT ?= /dev/ttyACM1
MCU   = atmega328p
F_CPU = 16000000UL

all: ppt_uno.hex

ppt_uno.elf: ppt_uno.c
	avr-gcc -mmcu=$(MCU) -DF_CPU=$(F_CPU) -Os -Wall -Wextra -o $@ $<
	avr-size $@

ppt_uno.hex: ppt_uno.elf
	avr-objcopy -O ihex $< $@

flash: ppt_uno.hex
	avrdude -q -c arduino -p m328p -P $(PORT) -b 115200 -U flash:w:$<:i

cert:
	python3 certify_uno.py --port $(PORT)

clean:
	rm -f ppt_uno.elf ppt_uno.hex

.PHONY: all flash cert clean
