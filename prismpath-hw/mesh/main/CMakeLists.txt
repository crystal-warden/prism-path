idf_component_register(SRCS "ppt_mesh.c" "mesh_node.c" "../../dist/pp_dist.c" "monocypher.c" "monocypher-ed25519.c"
                       INCLUDE_DIRS "." "../../dist"
                       REQUIRES esp_wifi nvs_flash esp_netif esp_event driver esp_timer)
