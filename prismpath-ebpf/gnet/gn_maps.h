// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
/* gn_maps.h: the governed net program's own maps, beside the table maps of ../ppt_eval_bpf.h. Declared in
 * one place so the kernel program and its userspace test path (gn_batch.c) hold the same layout. */
#pragma once

#include "gn_common.h"

/* written last by the loader: `loaded` set to 1 only after every table map and the actions are in */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct gn_config);
         __uint(max_entries, 1); } gn_config_map SEC(".maps");
/* one action per rule of the start node, by matched edge index */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __type(key, __u32); __type(value, struct gn_action);
         __uint(max_entries, GN_MAX_RULES); } gn_action_map SEC(".maps");
