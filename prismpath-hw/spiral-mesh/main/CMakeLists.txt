idf_component_register(SRCS "mesh_node.c" INCLUDE_DIRS "." PRIV_REQUIRES nvs_flash esp_wifi esp_netif esp_event)
if(DEFINED ENV{BATCH_TICKS})
  target_compile_definitions(${COMPONENT_LIB} PRIVATE BATCH_TICKS=$ENV{BATCH_TICKS})
endif()
