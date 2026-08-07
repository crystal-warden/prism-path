# AXI wrapper testbench — `make -C tb/axi`
SIM ?= verilator
TOPLEVEL_LANG ?= verilog

VERILOG_SOURCES = $(PWD)/../../rtl/ppt_interp.sv $(PWD)/../../rtl/ppt_axi.sv
COCOTB_TOPLEVEL = ppt_axi
COCOTB_TEST_MODULES = test_ppt_axi

TOPLEVEL = $(COCOTB_TOPLEVEL)
MODULE = $(COCOTB_TEST_MODULES)

include $(shell cocotb-config --makefiles)/Makefile.sim
