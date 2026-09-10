if(DEFINED ENV{C6_APP} AND "$ENV{C6_APP}" STREQUAL "host")
  idf_component_register(SRCS "relay_host.c" REQUIRES ieee802154 driver esp_timer)
else()
  idf_component_register(SRCS "relay_air.c" REQUIRES ieee802154 esp_wifi nvs_flash esp_netif esp_event esp_timer driver lwip)
endif()
# bring up switches, e.g. C6_DEFS="HOP_NO_154;ANT3=1"
if(DEFINED ENV{C6_DEFS})
  target_compile_definitions(${COMPONENT_LIB} PRIVATE $ENV{C6_DEFS})
endif()
