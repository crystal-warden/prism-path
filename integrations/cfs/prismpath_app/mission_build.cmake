# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# PRISMPATH_APP mission build setup: the mission-wide configuration headers, each overridable by a mission.
set(PRISMPATH_APP_MISSION_CONFIG_FILE_LIST
  prismpath_app_interface_cfg_values.h
  prismpath_app_mission_cfg.h
  prismpath_app_perfids.h
  prismpath_app_msg.h
  prismpath_app_topicid_values.h
)

generate_configfile_set(${PRISMPATH_APP_MISSION_CONFIG_FILE_LIST})
