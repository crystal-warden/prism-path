# PrismPath PPT interpreter on RP2350 (Pico 2). Board + platform (rp2350-arm-s / rp2350-riscv) and
# PICO_SDK_PATH are passed by the Makefile via -D. One source, two ISAs.
cmake_minimum_required(VERSION 3.13)

include(pico_sdk_import.cmake)

project(ppt_rp2350 C CXX ASM)
pico_sdk_init()

add_executable(ppt_rp2350 ppt_rp2350.c)
target_link_libraries(ppt_rp2350 pico_stdlib)

# Binary wire protocol over native USB-CDC; no UART, no stdio on the pins.
pico_enable_stdio_usb(ppt_rp2350 1)
pico_enable_stdio_uart(ppt_rp2350 0)

pico_add_extra_outputs(ppt_rp2350)   # .uf2 + .hex + .bin + map
