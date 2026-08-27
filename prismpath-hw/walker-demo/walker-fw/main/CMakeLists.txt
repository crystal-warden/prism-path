idf_component_register(
  SRCS "walker.c"
       "sh2/sh2.c" "sh2/shtp.c" "sh2/sh2_SensorValue.c" "sh2/sh2_util.c" "sh2/euler.c"
  INCLUDE_DIRS "sh2"
  REQUIRES driver esp_timer nvs_flash esp_wifi esp_netif esp_event)
