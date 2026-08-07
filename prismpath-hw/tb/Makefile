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

include $(shell cocotb-config --makefiles)/Makefile.sim
