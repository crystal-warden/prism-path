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

# generate_configfile_set is the cFS bundle's (cFE 7). An older cFE, such as the one NOS3 carries, has only
# generate_config_includefile, so the same wrappers are made with it: a mission's own file of the same name wins,
# else the default_ one in config/.
if (COMMAND generate_configfile_set)
  generate_configfile_set(${PRISMPATH_APP_PLATFORM_CONFIG_FILE_LIST})
else()
  foreach(_PP_CFGFILE ${PRISMPATH_APP_PLATFORM_CONFIG_FILE_LIST})
    generate_config_includefile(FILE_NAME "${_PP_CFGFILE}"
                                FALLBACK_FILE "${CMAKE_CURRENT_LIST_DIR}/config/default_${_PP_CFGFILE}")
  endforeach()
endif()
