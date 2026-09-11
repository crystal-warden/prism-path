# Entry points in one firmware directory, selected by VISION_APP: t0 (capture envelope, default), snap
# (the aiming tool on the console), rec (the corpus recorder over native USB).
if(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "snap")
  idf_component_register(SRCS "vision_snap.c" REQUIRES esp_timer mbedtls driver)
elseif(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "rec")
  idf_component_register(SRCS "vision_rec.c" REQUIRES esp_timer driver)
elseif(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "replay")
  idf_component_register(SRCS "vision_replay.c" REQUIRES esp_timer driver)
elseif(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "live")
  idf_component_register(SRCS "vision_live.c" REQUIRES esp_timer driver)
elseif(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "radio")
  idf_component_register(SRCS "vision_radio_node.c" REQUIRES esp_timer driver esp_wifi nvs_flash esp_netif esp_event lwip mbedtls)
elseif(DEFINED ENV{VISION_APP} AND "$ENV{VISION_APP}" STREQUAL "relay")
  idf_component_register(SRCS "vision_relay.c" REQUIRES esp_timer driver esp_wifi nvs_flash esp_netif esp_event)
else()
  idf_component_register(SRCS "vision_t0.c" REQUIRES esp_timer mbedtls)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE T0_SECONDS=15)
endif()

# build switches, e.g. VISION_DEFS="VISION_VGA"
if(DEFINED ENV{VISION_DEFS})
  target_compile_definitions(${COMPONENT_LIB} PRIVATE $ENV{VISION_DEFS})
endif()
