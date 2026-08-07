CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

all: build/interp

build/interp: interp.c | build
	$(CC) $(CFLAGS) -o $@ $<

build:
	mkdir -p build

cert: build/interp
	python3 run_vectors.py

clean:
	rm -rf build

.PHONY: all cert clean
