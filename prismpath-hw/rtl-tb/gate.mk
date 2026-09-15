# The shared cocotb gate, included by every testbench Makefile in rtl-tb/ and codec-bench/rtl-tb/.
#
# Why this file exists. `make sim`, and so a bare `make`, exits 0 even when a cocotb test FAILS: the
# simulator finishes cleanly and cocotb records the failure in results.xml, not in the make exit
# code. Ten of the eleven testbench Makefiles here used to end at `include Makefile.sim` with no
# gate, so following the command printed in their own header gave a green build on broken RTL. Only
# prismpath-hw/tb had a real gate. This file hands every other testbench the same one, decided by
# the same checker, prismpath-hw/tb/check_results.py.
#
# A Makefile that includes this must set two variables first:
#
#   GATE_NAME      one short word naming the testbench. It names both the results file and the
#                  scratch build directory, so testbenches that share a directory stop overwriting
#                  each other and a failure survives the next testbench's run.
#   GATE_EXPECTED  the cocotb test names that must appear in the results. A test that was renamed,
#                  skipped, or never reached is then a red gate instead of a silent pass.
#
# The include must come BEFORE `include Makefile.sim`. cocotb's Makefile.inc defaults
# COCOTB_RESULTS_FILE and SIM_BUILD with `?=` and the simulator fragment immediately writes rules
# whose target names expand those two, so an override read afterwards would move neither.
#
# `gate` is the default target of every Makefile that includes this, which is the point: there is no
# longer a spelling of `make` in these directories that runs the simulation without judging it.
# `make -f Makefile.<name> sim` still runs the simulation alone, for waveform work.

ifeq ($(strip $(GATE_NAME)),)
  $(error gate.mk: set GATE_NAME before including it)
endif
ifeq ($(strip $(GATE_EXPECTED)),)
  $(error gate.mk: set GATE_EXPECTED before including it)
endif

# The including Makefile is the first entry of MAKEFILE_LIST and this file is the last one so far,
# so both are known here without either side hard coding the other's path. The recursive make below
# needs the first because these Makefiles are not named `Makefile`; the checker path needs the
# second because codec-bench/rtl-tb includes this file from two directories away.
GATE_MAKEFILE := $(firstword $(MAKEFILE_LIST))
GATE_CHECKER := $(dir $(lastword $(MAKEFILE_LIST)))../tb/check_results.py

COCOTB_RESULTS_FILE = results.$(GATE_NAME).xml
SIM_BUILD = sim_build/$(GATE_NAME)

.PHONY: gate
gate:
	rm -f $(COCOTB_RESULTS_FILE)
	$(MAKE) -f $(GATE_MAKEFILE) sim
	python3 $(GATE_CHECKER) --results $(COCOTB_RESULTS_FILE) --expect $(GATE_EXPECTED)
