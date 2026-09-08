-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC

import Lake
open Lake DSL

/-!
# Lake Configuration for Figueroa Quantization (FQ)

Note: Nothing in this directory has been compiled yet. Lean 4 and Mathlib are not installed.

## Specification Decisions (HANDOFF Section 4)

1. Domain is the Integers (Int):
   Numeric fields operating in Figueroa Quantization are integer-valued (Int). Float literals and
   real-valued bounds are excluded.

2. Total Readings:
   Quantization and evaluation quantify over total readings containing all decision-relevant fields.

3. Coarsest Partition as Separate Claim (I1b):
   Theorem I1 (decision preservation) is separated from I1b (minimum sufficient statistic / coarsest partition).

4. Categorical Other Cell:
   Categorical field partitions include a trailing fallback cell for unmatched string constants.

5. Booleans:
   Boolean fields use a 2-cell partition (0 for false, 1 for true) preserving boolean truthiness.
-/

package «FQ» where
  -- Package configuration options

require mathlib from git
  "https://github.com/leanprover-community/mathlib4.git" @ "v4.12.0"

@[default_target]
lean_lib «FQ» where
  -- Library configuration options
