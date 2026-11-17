#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Add the PrismPath app to a cFS checkout: link it into apps/, list it in the mission's targets.cmake and add its
# line to the startup script generator. Safe to run again. It edits the cFS checkout, never this repository.
#
#   integrations/cfs/stage.sh /path/to/cFS
set -euo pipefail
CFS="${1:?usage: stage.sh <path to a cFS checkout>}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[ -d "$CFS/apps" ] && [ -f "$CFS/sample_defs/targets.cmake" ] || { echo "$CFS is not a cFS bundle checkout" >&2; exit 2; }

ln -sfn "$HERE/prismpath_app" "$CFS/apps/prismpath_app"

# the app is built for every CPU the mission builds, so it goes in the global list (not in a cpuN_APPLIST)
if ! grep -q 'prismpath_app' "$CFS/sample_defs/targets.cmake"; then
  sed -i 's/^list(APPEND MISSION_GLOBAL_APPLIST sample_app sample_lib)/list(APPEND MISSION_GLOBAL_APPLIST sample_app sample_lib prismpath_app)/' \
    "$CFS/sample_defs/targets.cmake"
  grep -q 'prismpath_app' "$CFS/sample_defs/targets.cmake" || { echo "could not find the sample_app line in targets.cmake; add prismpath_app to MISSION_GLOBAL_APPLIST by hand" >&2; exit 3; }
fi

# the startup script is written by sample_defs/generate_startup.cmake; the new line follows the sample_app one
if ! grep -q 'prismpath_app' "$CFS/sample_defs/generate_startup.cmake"; then
  sed -i 's|^\(\s*\)"CFE_APP, sample_app,  SAMPLE_APP_Main,    SAMPLE_APP,   50,   32768, 0x0, 0;\\n"|&\n\1"CFE_APP, prismpath_app, PRISMPATH_APP_Main, PRISMPATH_APP, 51, 32768, 0x0, 0;\\n"|' \
    "$CFS/sample_defs/generate_startup.cmake"
  grep -q 'prismpath_app' "$CFS/sample_defs/generate_startup.cmake" || { echo "could not find the sample_app line in generate_startup.cmake; add CFE_APP, prismpath_app, PRISMPATH_APP_Main, PRISMPATH_APP, 51, 32768, 0x0, 0; by hand" >&2; exit 3; }
fi
echo "prismpath_app staged in $CFS; build with: PRISMPATH_HW_DIR=$HERE/../../prismpath-hw make -C $CFS native_std.prep native_std.install"
