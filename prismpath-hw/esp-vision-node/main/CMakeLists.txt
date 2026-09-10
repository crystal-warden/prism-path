# Two entry points, one firmware directory: T0 (capture envelope) or SNAP (the aiming tool).
if(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "snap")
  idf_component_register(SRCS "vision_snap.c" REQUIRES esp_timer mbedtls driver)
else()
  idf_component_register(SRCS "vision_t0.c" REQUIRES esp_timer mbedtls)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE T0_SECONDS=15)
endif()
