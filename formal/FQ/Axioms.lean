-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.I1
import FQ.Reconstruct
import FQ.Zeckendorf
import FQ.AlgEq
import FQ.Spiral
/-! The axiom audit: the theorem must depend on nothing beyond Lean's three standard axioms. -/
#print axioms FQ.decision_preservation
#print axioms FQ.symbolCount_eq_truthVec
#print axioms FQ.reconstruct_route
#print axioms FQ.coarsest_interval
#print axioms FQ.Zeck.decode_encode
#print axioms FQ.Zeck.takeCode_encode
#print axioms FQ.Zeck.decodeStream_flatMap
#print axioms FQ.symbolAlg_eq_symbolCount
#print axioms FQ.symbolAlg_eq_truthVec
#print axioms FQ.Spiral.gray_perm_product
#print axioms FQ.Spiral.spiral_bijection
#print axioms FQ.Spiral.band_route
#print axioms FQ.Spiral.band_eq_route_eq
