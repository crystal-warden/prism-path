CC      ?= cc
CFLAGS  ?= -O2 -Wall -Wextra -std=c11

all: build/interp build/interp_hdr

build/interp: interp.c | build
	$(CC) $(CFLAGS) -o $@ $<

build/interp_hdr: interp_hdr.c ppt_eval.h | build
	$(CC) $(CFLAGS) -o $@ $<

build:
	mkdir -p build

cert: build/interp build/interp_hdr
	python3 run_vectors.py
	python3 run_vectors.py --interp build/interp_hdr
	python3 eval_copies_check.py

clean:
	rm -rf build

.PHONY: all cert clean
