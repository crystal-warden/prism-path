# Makefile — PrismPath PPT v1 eBPF/XDP target.
#
# The third certified substrate for a decidable ("Level M") PrismPath table:
#   Python reference  ->  FPGA C-table (../prismpath-hw)  ->  eBPF/XDP (here).
# The PPT binary format and the reference interpreter are canonical in ../prismpath-hw; this target
# references them (single source of truth) rather than copying. See README.md for the verifier analysis.

CLANG ?= clang
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra
BPF_CFLAGS ?= -O2 -Wall -target bpf -g -I/usr/include -I/usr/include/$(shell uname -m)-linux-gnu -I.

HWDIR      ?= ../prismpath-hw
INTERP_SRC := $(HWDIR)/interp.c

CLANG_EXISTS  := $(shell which $(CLANG) >/dev/null 2>&1 && echo 1 || echo 0)
LIBBPF_EXISTS := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1 || echo 0)

all: ppt_xdp.bpf.o ppt_net.bpf.o facet_decode.bpf.o ppt_select.bpf.o a6/ppt_xdp.bpf.o loader interp tools

# the stateful selector and the decode and rewrite variant (a6) are built too, so a clang or header change that
# breaks them fails the build instead of waiting for the next bench session
ppt_select.bpf.o: ppt_select.bpf.c ppt_common.h
	@if [ $(CLANG_EXISTS) -eq 1 ]; then $(CLANG) $(BPF_CFLAGS) -c ppt_select.bpf.c -o ppt_select.bpf.o; else echo "[NOTICE] $(CLANG) not found"; fi

a6/ppt_xdp.bpf.o: a6/ppt_xdp.bpf.c ppt_common.h
	@if [ $(CLANG_EXISTS) -eq 1 ]; then $(CLANG) $(BPF_CFLAGS) -c a6/ppt_xdp.bpf.c -o a6/ppt_xdp.bpf.o; else echo "[NOTICE] $(CLANG) not found"; fi

# host tools for the selector sessions (need libbpf; skipped without it, like the loader's fallback)
TOOLS := cert_selector migrate_selector receipts_selector seal_receipts smoke_selector
tools: $(TOOLS)
$(TOOLS): %: %.c ppt_common.h
	@if [ $(LIBBPF_EXISTS) -eq 1 ]; then $(CC) $(CFLAGS) $< $$(pkg-config --cflags --libs libbpf) -lelf -lz -lpthread -lcrypto -o $@; else echo "[NOTICE] libbpf not found, $@ not built"; fi

# Reference C interpreter, built from prismpath-hw's canonical source — smoke.sh checks parity against it.
interp: $(INTERP_SRC)
	$(CC) $(CFLAGS) -o interp $(INTERP_SRC)

ppt_xdp.bpf.o: ppt_xdp.bpf.c ppt_common.h
	@if [ $(CLANG_EXISTS) -eq 1 ]; then \
		echo "Building eBPF program $(CLANG)..."; \
		$(CLANG) $(BPF_CFLAGS) -c ppt_xdp.bpf.c -o ppt_xdp.bpf.o; \
	else \
		echo "[NOTICE] $(CLANG) not found — install clang/llvm/libbpf-dev to build the BPF object."; \
	fi

ppt_net.bpf.o: ppt_net.bpf.c ppt_common.h
	@if [ $(CLANG_EXISTS) -eq 1 ]; then \
		echo "Building eBPF real-packet program $(CLANG)..."; \
		$(CLANG) $(BPF_CFLAGS) -c ppt_net.bpf.c -o ppt_net.bpf.o; \
	else \
		echo "[NOTICE] $(CLANG) not found — install clang/llvm/libbpf-dev to build the BPF object."; \
	fi

facet_decode.bpf.o: facet_decode.bpf.c
	@if [ $(CLANG_EXISTS) -eq 1 ]; then \
		echo "Building eBPF decode-plane $(CLANG)..."; \
		$(CLANG) $(BPF_CFLAGS) -c facet_decode.bpf.c -o facet_decode.bpf.o; \
	else \
		echo "[NOTICE] $(CLANG) not found — install clang/llvm/libbpf-dev to build the BPF object."; \
	fi

loader: loader.c ppt_common.h
	@if [ $(LIBBPF_EXISTS) -eq 1 ]; then \
		echo "Building loader with libbpf..."; \
		$(CC) $(CFLAGS) loader.c $$(pkg-config --cflags --libs libbpf) -lelf -lz -lpthread -lcrypto -o loader; \
	else \
		echo "Building loader (standalone/fallback -DNO_LIBBPF)..."; \
		$(CC) $(CFLAGS) -DNO_LIBBPF loader.c -o loader; \
	fi

clean:
	rm -f ppt_xdp.bpf.o ppt_net.bpf.o facet_decode.bpf.o ppt_select.bpf.o a6/ppt_xdp.bpf.o loader interp $(TOOLS) smoke.out scratch/regs*.bin

# Host-parity + (as root) full kernel verify/attach/execute. Captures smoke.out; preserves exit code.
smoke: all
	@bash smoke.sh > smoke.out 2>&1; rc=$$?; cat smoke.out; exit $$rc

.PHONY: all clean smoke tools
