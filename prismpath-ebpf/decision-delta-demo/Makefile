# Build the receipt-draining forwarder against the selector sources one level up (prismpath-ebpf/).
# On the Protectli build box, the sources also live alongside in ~/prismpath-sel/; either -I.. here
# or building in that dir works because #include "loader.c" searches the include path.
CC      ?= gcc
CLANG   ?= clang
BPFCFL  := -O2 -target bpf -I..
CFLAGS  := -O2 -Wno-unused-function -I..
LIBS    := -lcrypto $(shell pkg-config --libs libbpf 2>/dev/null || echo -lbpf)

all: ppt_select.bpf.o sel_forward_receipts

ppt_select.bpf.o: ../ppt_select.bpf.c ../ppt_common.h
	$(CLANG) $(BPFCFL) -c $< -o $@

sel_forward_receipts: sel_forward_receipts.c ../loader.c ../ppt_common.h
	$(CC) $(CFLAGS) sel_forward_receipts.c -o $@ $(LIBS)

clean:
	rm -f sel_forward_receipts ppt_select.bpf.o

.PHONY: all clean
