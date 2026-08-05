#!/usr/bin/env bash
# Drive agy over the 9 per-control prompts on ONE session (--continue), 5s sleep between (anti-hang).
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.local/bin:$PATH"
mkdir -p efficacy/agy_logs
ORDER=$(python3 -c "import json;print(chr(32).join(json.load(open(\"efficacy/prompts/_order.json\"))))")
first=1
for cid in $ORDER; do
  [ $first -eq 0 ] && sleep 5
  PROMPT="$(cat efficacy/prompts/$cid.txt)"
  if [ $first -eq 1 ]; then
    agy -p "$PROMPT" --add-dir "$PWD" --print-timeout 8m > efficacy/agy_logs/$cid.out 2>&1; rc=$?
    first=0
  else
    agy --continue -p "$PROMPT" --add-dir "$PWD" --print-timeout 8m > efficacy/agy_logs/$cid.out 2>&1; rc=$?
  fi
  echo "[loop] $cid rc=$rc :: $(tail -1 efficacy/agy_logs/$cid.out 2>/dev/null)"
done
echo "ALL_DONE files=$(ls efficacy/corpus/*.json 2>/dev/null | grep -v _manifest | wc -l)"
