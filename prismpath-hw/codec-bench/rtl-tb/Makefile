# cocotb tb: the RTL Zeckendorf encoder vs the same reference generated corpus the MCU bench used.
#   make                         the gate: runs the sim, then fails on any cocotb failure
SIM ?= verilator
TOPLEVEL_LANG ?= verilog
VERILOG_SOURCES = $(PWD)/../../rtl/zeck_enc.sv
COCOTB_TOPLEVEL = zeck_enc
COCOTB_TEST_MODULES = test_zeck_enc
TOPLEVEL = $(COCOTB_TOPLEVEL)
MODULE = $(COCOTB_TEST_MODULES)
GATE_NAME = zeck_enc
GATE_EXPECTED = conformance
include ../../rtl-tb/gate.mk
include $(shell cocotb-config --makefiles)/Makefile.sim
