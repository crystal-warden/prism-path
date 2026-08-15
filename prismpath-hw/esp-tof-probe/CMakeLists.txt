# Throwaway ESP-IDF probe: verify VL53L0X ToF wiring on the mesh ESP32s (GPIO21/22).
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(tof_probe)
