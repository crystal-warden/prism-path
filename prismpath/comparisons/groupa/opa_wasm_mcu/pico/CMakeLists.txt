# OPA WebAssembly module under the wasm3 interpreter on the RP2350. WASM3_SRC points at the wasm3
# source directory (a third party MIT licensed interpreter, cloned by toolchain/install.sh into
# comparisons/.toolchain/src/wasm3, never vendored into this repository).
cmake_minimum_required(VERSION 3.13)
include(pico_sdk_import.cmake)
project(opa_pico C CXX ASM)
pico_sdk_init()
if(NOT WASM3_SRC)
  set(WASM3_SRC ${CMAKE_CURRENT_LIST_DIR}/../../../.toolchain/src/wasm3/source)
endif()
set(WASM3_CORE m3_bind.c m3_code.c m3_compile.c m3_core.c m3_env.c m3_exec.c m3_function.c m3_info.c m3_module.c m3_parse.c m3_validate.c)
list(TRANSFORM WASM3_CORE PREPEND ${WASM3_SRC}/ OUTPUT_VARIABLE WASM3_SOURCES)
add_executable(opa_pico opa_pico.c ../opa_wasm_eval.c ${WASM3_SOURCES})
if(NOT WASM_HDR_DIR)
  set(WASM_HDR_DIR ${CMAKE_CURRENT_LIST_DIR}/build/gen)
endif()
target_include_directories(opa_pico PRIVATE ${WASM3_SRC} ${CMAKE_CURRENT_LIST_DIR}/.. ${WASM_HDR_DIR})
target_compile_definitions(opa_pico PRIVATE d_m3HasWASI=0 d_m3HasFloat=1 d_m3MaxLinearMemoryPages=6
  d_m3MaxFunctionStackHeight=2000 d_m3VerboseErrorMessages=1 d_m3HasTracer=0 ISA_NAME="${ISA_NAME}")
target_compile_options(opa_pico PRIVATE -Os -Wno-unused-function -Wno-unused-variable)
target_link_libraries(opa_pico pico_stdlib)
pico_enable_stdio_usb(opa_pico 1)
pico_enable_stdio_uart(opa_pico 0)
pico_add_extra_outputs(opa_pico)
