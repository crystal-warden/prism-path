#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the paper from paper.md into OUT_DIR (default out/, not tracked): PAPER.tex, a MathML PAPER.html that
# reads offline, and PAPER.pdf through tectonic. The DOI assigned on publication is the one input; without it
# the front matter says the DOI is assigned on publication.
#
#   DOI=10.5281/zenodo.NNNNNNN ./build_manuscript.sh [OUT_DIR]
set -euo pipefail
cd "$(dirname "$0")"
OUT="${1:-out}"
TITLE="Governed Autonomous Execution: Authority Separation and Semantic Invariance Across Execution Boundaries"
AUTHOR="A. Figueroa, Crystal Warden Labs"
FMT="gfm+tex_math_dollars"
if [ -n "${DOI:-}" ]; then
  DOI_LINE="doi:${DOI}."
  DATE="Preprint, September 2026. doi:${DOI}"
else
  DOI_LINE="The DOI is assigned on publication."
  DATE="Preprint, September 2026"
fi

command -v pandoc >/dev/null || { echo "pandoc is required" >&2; exit 1; }
rm -rf "$OUT"; mkdir -p "$OUT"

# The source carries one DOI slot in its front matter.
sed "s#{{DOI_LINE}}#${DOI_LINE}#" paper.md > "$OUT/paper.md"
grep -q "{{DOI_LINE}}" "$OUT/paper.md" && { echo "DOI slot not filled" >&2; exit 1; }

# The LaTeX body starts at the abstract; title, author and date travel as metadata.
awk 'f{print} /^## Abstract/{f=1; print}' "$OUT/paper.md" > "$OUT/body.md"

cat > "$OUT/header.html" <<'CSS'
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: light dark; }
  body { max-width: 720px; margin: 0 auto; padding: 1.4rem 1.1rem 4rem;
         font-family: Georgia, "Times New Roman", serif; font-size: 1.06rem; line-height: 1.62;
         color: #1a1a1a; background: #fbfbf9; }
  h1 { font-size: 1.7rem; line-height: 1.25; margin: 0 0 .2rem; }
  h2 { font-size: 1.28rem; margin: 2.1rem 0 .6rem; border-top: 1px solid #ddd; padding-top: .3rem; }
  h1 + h2 { border-top: none; font-weight: 600; color: #444; font-size: 1.12rem; }
  h3 { font-size: 1.08rem; margin: 1.3rem 0 .4rem; }
  code { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: .9em;
         background: rgba(0,0,0,.05); padding: .05em .3em; border-radius: 3px; }
  table { border-collapse: collapse; font-size: .92rem; } td, th { padding: .25rem .5rem; vertical-align: top; }
  @media (prefers-color-scheme: dark) {
    body { color: #e6e6e6; background: #17171a; }
    h2 { border-top-color: #333; } h1 + h2 { color: #aaa; } code { background: rgba(255,255,255,.08); }
  }
</style>
CSS

echo "[tex]  $OUT/PAPER.tex"
pandoc "$OUT/body.md" -f "$FMT" -s -t latex --toc \
  --metadata title="$TITLE" --metadata author="$AUTHOR" --metadata date="$DATE" \
  -o "$OUT/PAPER.tex"

# The section 7 evidence table is the one wide table; pandoc gives it natural width columns that overflow
# the page, so it is constrained to wrapping columns before the PDF is built.
python3 fix_table_widths.py "$OUT/PAPER.tex"

# The supplementary artifact list is short and closes the paper, so it starts on a fresh page rather than
# splitting its bullets away from its heading.
python3 - "$OUT/PAPER.tex" <<'PYEOF'
import sys
path = sys.argv[1]
t = open(path, encoding="utf-8").read()
head = "\\subsection{Supplementary artifacts}"
if t.count(head) != 1:
    sys.exit("supplementary heading: expected exactly 1, found %d" % t.count(head))
open(path, "w", encoding="utf-8").write(t.replace(head, "\\clearpage\n" + head, 1))
PYEOF

echo "[html] $OUT/PAPER.html"
pandoc "$OUT/paper.md" -f "$FMT" -t html5 -s --mathml \
  --include-in-header "$OUT/header.html" --metadata title="Governed Autonomous Execution" \
  -o "$OUT/PAPER.html"
rm -f "$OUT/body.md" "$OUT/header.html"

if command -v tectonic >/dev/null 2>&1; then
  echo "[pdf]  $OUT/PAPER.pdf (tectonic)"
  ( cd "$OUT" && tectonic PAPER.tex >/dev/null 2>&1 ) && echo "  built" || { echo "  tectonic failed; run: tectonic $OUT/PAPER.tex" >&2; exit 1; }
else
  echo "[pdf]  skipped (no tectonic)"
fi
