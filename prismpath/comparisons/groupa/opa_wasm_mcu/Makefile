# OPA wasm under wasm3: Linux reference host and the RP2350 firmware (both ISAs).
#   make linux                        -> build_linux/opa_host_linux
#   make arm                          -> pico/build/arm/opa_pico.uf2
#   make riscv RISCV_TOOLCHAIN=<dir>  -> pico/build/riscv/opa_pico.uf2
WASM3_SRC       ?= $(abspath ../../.toolchain/src/wasm3/source)
PICO_SDK_PATH   ?= /home/cwadmin/cwprojects/pico-sdk
RISCV_TOOLCHAIN ?= /home/cwadmin/cwprojects/riscv-toolchain
linux:
	mkdir -p build_linux && gcc -O2 -Dd_m3HasWASI=0 -I$(WASM3_SRC) -I. -o build_linux/opa_host_linux opa_host_linux.c opa_wasm_eval.c $(WASM3_SRC)/m3_*.c -lm
arm:
	cmake -S pico -B pico/build/arm -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-arm-s -DWASM3_SRC=$(WASM3_SRC) -DISA_NAME=rp2350-arm
	cmake --build pico/build/arm -j
riscv:
	cmake -S pico -B pico/build/riscv -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-riscv -DPICO_TOOLCHAIN_PATH=$(RISCV_TOOLCHAIN) -DWASM3_SRC=$(WASM3_SRC) -DISA_NAME=rp2350-riscv
	cmake --build pico/build/riscv -j
clean:
	rm -rf build_linux pico/build
.PHONY: linux arm riscv clean
