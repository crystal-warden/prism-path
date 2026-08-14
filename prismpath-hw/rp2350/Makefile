# Build the RP2350 PPT interpreter for both ISAs of the chip from one source.
#   make arm                          -> build/arm/ppt_rp2350.uf2    (Cortex-M33)
#   make riscv RISCV_TOOLCHAIN=<dir>  -> build/riscv/ppt_rp2350.uf2  (Hazard3 RISC-V)
#   make flash-arm | flash-riscv      (copy the .uf2 to a BOOTSEL-mounted RP2350)
#
# The ARM toolchain is Ubuntu's gcc-arm-none-eabi. The RP2350 RISC-V target needs a newlib
# toolchain (Ubuntu's gcc-riscv64-unknown-elf lacks nosys.specs) — pass the Raspberry Pi
# riscv-toolchain (prefix riscv32-unknown-elf-, the SDK default) via RISCV_TOOLCHAIN=<its dir>.
PICO_SDK_PATH   ?= /home/cwadmin/cwprojects/pico-sdk
BOARD           ?= pico2
RP2350_MOUNT    ?= /media/$(USER)/RP2350
RISCV_TOOLCHAIN ?=

arm: build/arm/ppt_rp2350.uf2
build/arm/ppt_rp2350.uf2:
	cmake -S . -B build/arm -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=$(BOARD) \
		-DPICO_PLATFORM=rp2350-arm-s
	cmake --build build/arm -j

riscv: build/riscv/ppt_rp2350.uf2
build/riscv/ppt_rp2350.uf2:
	cmake -S . -B build/riscv -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=$(BOARD) \
		-DPICO_PLATFORM=rp2350-riscv $(if $(RISCV_TOOLCHAIN),-DPICO_TOOLCHAIN_PATH=$(RISCV_TOOLCHAIN))
	cmake --build build/riscv -j

flash-arm: build/arm/ppt_rp2350.uf2
	cp build/arm/ppt_rp2350.uf2 $(RP2350_MOUNT)/ && sync

flash-riscv: build/riscv/ppt_rp2350.uf2
	cp build/riscv/ppt_rp2350.uf2 $(RP2350_MOUNT)/ && sync

clean:
	rm -rf build

.PHONY: arm riscv flash-arm flash-riscv clean
