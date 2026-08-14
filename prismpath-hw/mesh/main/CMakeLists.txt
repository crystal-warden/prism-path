idf_component_register(SRCS "ppt_mesh.c" "monocypher.c" "monocypher-ed25519.c"
                       REQUIRES esp_wifi nvs_flash esp_netif esp_event driver esp_timer)
