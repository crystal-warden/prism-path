#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
# Constrain the one wide evidence table (section 7) to columns that wrap within the page.
# pandoc renders a pipe table as {@{}llll@{}}, natural-width columns that do not wrap, so the
# four-column evidence table runs past the right margin in the PDF. We rewrite just that column
# spec to fixed fractional p-columns with ragged-right wrapping, and set the table in a smaller
# font, without touching the document font. There is exactly one such table; if that ever changes
# this script fails loudly rather than guessing.
import sys

path = sys.argv[1]
t = open(path, encoding="utf-8").read()

old = r"\begin{longtable}[]{@{}llll@{}}"
cols = "".join(r">{\raggedright\arraybackslash}p{%s\linewidth}" % w
               for w in ("0.25", "0.35", "0.15", "0.19"))
new = "{\\footnotesize\\setlength{\\tabcolsep}{3pt}\n" + r"\begin{longtable}[]{@{}" + cols + r"@{}}"

n = t.count(old)
if n != 1:
    sys.exit("fix_table_widths: expected exactly 1 wide table, found %d" % n)

t = t.replace(old, new, 1)
t = t.replace(r"\end{longtable}", r"\end{longtable}}", 1)  # close the \footnotesize group
open(path, "w", encoding="utf-8").write(t)
print("fix_table_widths: evidence table set to wrapping columns")
