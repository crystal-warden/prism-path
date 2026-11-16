#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# Assemble the image's build context from this repository and a local Python environment.
#
#   sh build_context.sh OUT [PYTHON]
#
# OUT/app holds only what the webhook imports: the prismpath package (without its tests), the core's
# reference decision path (formal/diff/core_diff.py, core_policy.py, core_evidence.py), the governed
# harness and population packages (without tests, secrets or build output), and site/ with the
# `cryptography` package and its cffi support copied from PYTHON's environment (default: python3), which
# must be CPython 3.12 on aarch64 like the base image. OUT/Containerfile is the recipe.
set -eu
out=${1:?usage: build_context.sh OUT [PYTHON]}
python=${2:-python3}
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
if [ -e "$out" ]; then echo "build_context.sh: $out exists; refusing to replace it" >&2; exit 1; fi

ver=$("$python" -c 'import sys, platform; print(f"{sys.version_info[0]}.{sys.version_info[1]} {platform.machine()}")')
if [ "$ver" != "3.12 aarch64" ]; then
  echo "build_context.sh: $python is $ver; the image is CPython 3.12 on aarch64" >&2; exit 1
fi
site=$("$python" -c 'import cryptography, os; print(os.path.dirname(os.path.dirname(cryptography.__file__)))')

app="$out/app"
mkdir -p "$app/formal/diff" "$app/integrations" "$app/site"
copy_tree() {   # copy_tree SRC DST: Python sources and the policy images, no tests, caches, secrets or builds
  (cd "$1" && find . -type d \( -name tests -o -name __pycache__ -o -name secrets -o -name build \) -prune -o \
     -type f \( -name '*.py' -o -name '*.json' -o -name '*.md' \) -print) | while read -r f; do
    mkdir -p "$2/$(dirname "$f")"
    cp "$1/$f" "$2/$f"
  done
}
copy_tree "$repo/prismpath" "$app/prismpath"
for f in core_diff.py core_policy.py core_evidence.py; do cp "$repo/formal/diff/$f" "$app/formal/diff/$f"; done
cp "$repo/integrations/__init__.py" "$app/integrations/"
copy_tree "$repo/integrations/governed_harness" "$app/integrations/governed_harness"
copy_tree "$repo/integrations/governed_population" "$app/integrations/governed_population"
cp "$repo/LICENSE" "$repo/NOTICE" "$app/"

for name in cryptography cffi pycparser; do
  if [ -d "$site/$name" ]; then cp -R "$site/$name" "$app/site/"; fi
  for meta in "$site/$name"-*.dist-info; do [ -d "$meta" ] && cp -R "$meta" "$app/site/"; done
done
for so in "$site"/_cffi_backend*.so; do [ -e "$so" ] && cp "$so" "$app/site/"; done
find "$app" -name __pycache__ -type d -prune -exec rm -rf {} +
cp "$here/Containerfile" "$out/Containerfile"
echo "build_context.sh: context in $out ($(du -sh "$out" | cut -f1))"
