# OPA wasm under wasm3: Linux reference host and the RP2350 firmware (both ISAs).
#   make gen                          -> pico/build/gen/wasm_*.h from policy.rego with the pinned opa (never committed)
#   make linux                        -> build_linux/opa_host_linux
#   make arm                          -> pico/build/arm/opa_pico.uf2
#   make riscv RISCV_TOOLCHAIN=<dir>  -> pico/build/riscv/opa_pico.uf2
WASM3_SRC       ?= $(abspath ../../.toolchain/src/wasm3/source)
PICO_SDK_PATH   ?= /home/cwadmin/cwprojects/pico-sdk
RISCV_TOOLCHAIN ?= /home/cwadmin/cwprojects/riscv-toolchain
GEN = pico/build/gen
gen:
	python3 gen_wasm.py $(GEN)
linux:
	mkdir -p build_linux && gcc -O2 -Dd_m3HasWASI=0 -I$(WASM3_SRC) -I. -o build_linux/opa_host_linux opa_host_linux.c opa_wasm_eval.c $(WASM3_SRC)/m3_*.c -lm
arm: gen
	cmake -S pico -B pico/build/arm -DWASM_HDR_DIR=$(abspath $(GEN)) -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-arm-s -DWASM3_SRC=$(WASM3_SRC) -DISA_NAME=rp2350-arm
	cmake --build pico/build/arm -j
riscv: gen
	cmake -S pico -B pico/build/riscv -DWASM_HDR_DIR=$(abspath $(GEN)) -DPICO_SDK_PATH=$(PICO_SDK_PATH) -DPICO_BOARD=pico2 -DPICO_PLATFORM=rp2350-riscv -DPICO_TOOLCHAIN_PATH=$(RISCV_TOOLCHAIN) -DWASM3_SRC=$(WASM3_SRC) -DISA_NAME=rp2350-riscv
	cmake --build pico/build/riscv -j
clean:
	rm -rf build_linux pico/build
.PHONY: gen linux arm riscv clean
