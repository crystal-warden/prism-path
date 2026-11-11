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
import Core.Evidence
import Core.Canon2Proofs
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
#print axioms Core.Evidence.record
#print axioms Core.Evidence.verifyRun
#print axioms Core.Evidence.verified_receipt_is_verdict
#print axioms Core.Evidence.receipt_is_verdict_of_hashes
#print axioms Core.Evidence.verified_run_complete
#print axioms Core.Evidence.verified_refusal_registered
#print axioms Core.Evidence.verified_excluded_counter
#print axioms Core.Evidence.evidence_sound
#print axioms Core.Bridge.evalC_toX
#print axioms Core.Bridge.firstMatch_eq_routeX
#print axioms Core.Bridge.core_quantization_preserves
#print axioms Core.Bridge.core_reconstruct_route
#print axioms Core.Bridge.scaled_correct
#print axioms Core.Bridge.lowered_threshold_preserves
#print axioms Core.Bridge.boundary_canonical
#print axioms Core.Bridge.accepted_quantization_preserves
/-! The canon/2 encoding layer (formal/Core/Canon2.lean, Canon2Proofs.lean): the writer, the strict
reader, and the theorems that the writer and the reader are inverse on the canonical values. -/
#print axioms Core.readChars_wr
#print axioms Core.readChars_doc
#print axioms Core.readBytes_doc
#print axioms Core.keyLt_total
#print axioms Core.units_inj
#print axioms Core.sortM_sorted
#print axioms Core.canon_norm
#print axioms Core.norm_canon
#print axioms Core.read_write
#print axioms Core.read_write_doc
#print axioms Core.write_injective
#print axioms Core.canonical_form
#print axioms Core.same_value_same_spelling
#print axioms Core.readCanonical_iff
#print axioms Core.readCanonical_write
#print axioms Core.write_readCanonical
#print axioms Core.readCanonical_unique
#print axioms Core.readCanonical_refuses
#print axioms Core.readCanonical_cause
#print axioms Core.readCanonical_ok_iff
#print axioms Core.writeBytes
#print axioms Core.readCanonical
#print axioms Core.reader_not_canonical
#print axioms Core.noncanonical_image_refused
#print axioms Core.noncanonical_reading_refused
#print axioms Core.unreadable_bytes_refused
#print axioms Core.verdictBytes_canonical
#print axioms Core.route_canonical
#print axioms Core.decided_reading_unique
#print axioms Core.canonicalize
#print axioms Core.canonicalize_readCanonical
#print axioms Core.canonicalize_canonical
#print axioms Core.canonicalize_error_iff
#print axioms Core.canonicalize_idem
