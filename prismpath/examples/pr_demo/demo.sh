#!/usr/bin/env bash
# The money demo: "The PR is the process change."
#
# A PM changes ONE routing rule in prose — billing disputes over $500 now go to a human —
# as a Markdown diff. CI lints the flow and asserts the new routing with a fixture row.
# Merge. Production behavior changes. No deploy, no engineer, no framework.
#
# Run from the repo root:  bash examples/pr_demo/demo.sh
set -e
cd "$(dirname "$0")"
G='\033[0;32m'; C='\033[0;36m'; B='\033[1m'; N='\033[0m'

echo -e "${B}── The PR ─────────────────────────────────────────────────────${N}"
echo -e "${C}\$ git diff triage.md${N}"
diff -u triage.before.md triage.md | tail -n +3 | grep -E '^[-+@]' | head -20 || true
echo

echo -e "${B}── CI step 1: the flow compiles ───────────────────────────────${N}"
echo -e "${C}\$ prismpath validate triage.md${N}"
prismpath validate triage.md
echo

echo -e "${B}── CI step 2: the routing is asserted (no model, milliseconds) ─${N}"
echo -e "${C}\$ prismpath test triage.md${N}"
prismpath test triage.md
echo

echo -e "${B}── CI step 3: still in the portable subset ────────────────────${N}"
echo -e "${C}\$ prismpath portable triage.md${N}"
prismpath portable triage.md
echo
echo -e "${G}${B}Merge. Production routing changed. The PR was the process change.${N}"
