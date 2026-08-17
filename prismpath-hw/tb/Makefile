# cocotb testbench — `make -C tb` runs THE gate: RTL vs the frozen conformance corpus
SIM ?= verilator
TOPLEVEL_LANG ?= verilog

VERILOG_SOURCES = $(PWD)/../rtl/ppt_interp.sv
COCOTB_TOPLEVEL = ppt_interp
COCOTB_TEST_MODULES = test_ppt_interp

# legacy names for cocotb 1.x compatibility
TOPLEVEL = $(COCOTB_TOPLEVEL)
MODULE = $(COCOTB_TEST_MODULES)

EXTRA_ARGS += --trace-fst

# `make -C tb gate` is THE gate. Plain `make`/`make sim` returns 0 even when a cocotb test FAILS
# (Makefile.sim reports failure in results.xml, not in the exit code), so a bare `make` must NEVER be
# used as a pass/fail check. `gate` removes the stale result, runs the sim, then check_results.py
# fails the build on any failure/error or a test that did not run.
gate:
	rm -f results.xml
	$(MAKE) sim
	python3 check_results.py
.PHONY: gate

include $(shell cocotb-config --makefiles)/Makefile.sim
