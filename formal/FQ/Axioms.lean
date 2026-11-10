-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import FQ.I1
import FQ.Reconstruct
import FQ.Zeckendorf
import FQ.AlgEq
import FQ.Spiral
import FQ.Conversion
import FQ.Contract
import FQ.Absence
import Core.Bridge
import Core.Boundary
import Core.Codes
import Core.Order
import Core.Scope
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
#print axioms FQ.Conversion.convert_preserves
#print axioms FQ.Conversion.fixed_policy_preserved
#print axioms FQ.accept_faithful
#print axioms FQ.contract_a
#print axioms FQ.atomAbsent_is_engine_null
#print axioms FQ.absence_preservation
#print axioms FQ.reconstructX_route
/-! The verified core (formal/Core, docs/design/spec-verified-core.md): its theorems, and the
evaluator the oracle runs, which must not use `Classical.choice` to compute. -/
#print axioms Core.verdict
#print axioms Core.verdictBytes
#print axioms Core.verdict_total
#print axioms Core.matchSteps_le
#print axioms Core.firstMatch_spec
#print axioms Core.firstRefused_spec
#print axioms Core.policy_refusal_refuses_all
#print axioms Core.unreadable_image_refused
#print axioms Core.unreadable_reading_refused
#print axioms Core.boundary_refusal
#print axioms Core.route_sound
#print axioms Core.route_is_a_target
#print axioms Core.verdict_cases
#print axioms Core.policy_refusal_iff
#print axioms Core.decideReading_perm
#print axioms Core.verdict_perm
#print axioms Core.verdict_text_perm
#print axioms Core.readChars_wf
#print axioms Core.evalC_congr
#print axioms Core.refusal_registered
#print axioms Core.refusal_code_ne_zero
#print axioms Core.registry_codes_distinct
#print axioms Core.refusal_name_of_code
#print axioms Core.verdict_refusal_registered
#print axioms Core.lowerCond_first_atom
#print axioms Core.loadPolicy_first_problem
#print axioms Core.policy_cause_is_first
#print axioms Core.policy_accepted_iff_no_problem
#print axioms Core.verdict_policy_cause
#print axioms Core.policyCheck_of_systemBoundary
#print axioms Core.systemBoundary_of_policyCheck
#print axioms Core.policyCheck_refuses_routed
#print axioms Core.policyCheck_eq_systemBoundary
#print axioms Core.route_depends_on_routed
#print axioms Core.counterRefusal
#print axioms Core.counterRefusal_iff
#print axioms Core.counter_excluded_refused
#print axioms Core.Bridge.evalC_toX
#print axioms Core.Bridge.firstMatch_eq_routeX
#print axioms Core.Bridge.core_quantization_preserves
#print axioms Core.Bridge.core_reconstruct_route
#print axioms Core.Bridge.scaled_correct
#print axioms Core.Bridge.lowered_threshold_preserves
#print axioms Core.Bridge.boundary_canonical
#print axioms Core.Bridge.accepted_quantization_preserves
