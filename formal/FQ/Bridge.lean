-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.Partition
/-!
# Bridge checks (evaluated, not proven)

`#guard` evaluates a Bool at elaboration time and fails the build when it is false. These are the
executable checks that tie the canonical form the theorem is proven over to the reference algorithm
and to the three reference defects found in September 2026. Parity with the Python and Rust
implementations over the frozen corpus lives in `Vectors.lean` (generated) once the reference is
corrected.
-/

namespace FQ.Bridge
open FQ

def range (lo hi : Int) : List Int := (List.range (hi - lo + 1).toNat).map (fun i => lo + i)

/-- The two numeric forms agree on every value in a range. -/
def agree (atoms : List NumAtom) (lo hi : Int) : Bool :=
  (range lo hi).all (fun v => symbolAlg atoms v == symbolCount atoms v)

/-- Decision preservation on a range, for one field's atoms: equal symbols give equal truth vectors. -/
def preservesOn (atoms : List NumAtom) (lo hi : Int) : Bool :=
  let vs := range lo hi
  vs.all (fun v => vs.all (fun w => symbolCount atoms v != symbolCount atoms w || truthVec atoms v == truthVec atoms w))

-- The three reference defects, on the corrected construction.
def inList : List NumAtom := [.mem [3, 5]]
def notInList : List NumAtom := [.nmem [7]]
def truthyPlus : List NumAtom := [.cmp .ge 5, .truthy]
-- incident_severity's error_rate ladder and a mixed ladder.
def ladder : List NumAtom := [.cmp .ge 25, .cmp .ge 5, .cmp .ge 1]
def mixed : List NumAtom := [.cmp .lt 10, .cmp .le 10, .cmp .gt 10, .cmp .ge 10, .cmp .eq 3, .cmp .ne (-4), .mem [0, 7], .truthy]

#guard preservesOn inList (-10) 20
#guard preservesOn notInList (-10) 20
#guard preservesOn truthyPlus (-10) 20
#guard preservesOn ladder (-10) 60
#guard preservesOn mixed (-20) 30

#guard agree inList (-10) 20
#guard agree notInList (-10) 20
#guard agree truthyPlus (-10) 20
#guard agree ladder (-10) 60
#guard agree mixed (-20) 30

-- The defect itself, witnessed: under the reference's constant collection (ordering and equality
-- only) `x in (3, 5)` has no cut points, so 3 and 4 share a symbol while their truth differs.
def referenceConsts (atoms : List NumAtom) : List Int :=
  let raw := atoms.foldr (fun a acc => match a with | .cmp _ c => c :: acc | _ => acc) []
  ((if raw.isEmpty then [0] else raw).mergeSort (· ≤ ·)).eraseDups
def referenceSymbol (atoms : List NumAtom) (v : Int) : Nat :=
  (mergeCells atoms (fineGrid (referenceConsts atoms))).findIdx (·.contains v)
#guard referenceSymbol inList 3 == referenceSymbol inList 4
#guard truthVec inList 3 != truthVec inList 4
#guard referenceSymbol truthyPlus 0 == referenceSymbol truthyPlus 1
#guard truthVec truthyPlus 0 != truthVec truthyPlus 1

end FQ.Bridge
