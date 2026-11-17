# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# PRISMPATH_APP platform build setup: the per-target configuration headers, each overridable by a mission.
set(PRISMPATH_APP_PLATFORM_CONFIG_FILE_LIST
  prismpath_app_internal_cfg_values.h
  prismpath_app_platform_cfg.h
  prismpath_app_perfids.h
  prismpath_app_msgids.h
  prismpath_app_msgid_values.h
)

generate_configfile_set(${PRISMPATH_APP_PLATFORM_CONFIG_FILE_LIST})
