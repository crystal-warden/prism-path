# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# No Monocypher and no pp_dist.c: the relay is part of the untrusted transport and has nothing to check with (B10).
idf_component_register(SRCS "relay_main.c" "relay.c"
                       INCLUDE_DIRS "." "../../dist"
                       REQUIRES esp_wifi nvs_flash esp_netif esp_event driver)
