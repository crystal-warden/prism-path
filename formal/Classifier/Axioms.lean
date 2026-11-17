-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Lean
import Classifier.Theorems
/-!
# The classifier's axiom audit

Every theorem of `Classifier.Theorems` must depend on Lean's three standard axioms at most (`propext`,
`Classical.choice`, `Quot.sound`): `#assert_standard_axioms` prints each theorem's axioms and fails the build when
one depends on anything else (`sorryAx` included, so an unfinished proof cannot build).
-/

open Lean Elab Command in
elab "#assert_standard_axioms " id:ident : command => do
  let n ← liftCoreM <| realizeGlobalConstNoOverloadWithInfo id
  let axs ← liftCoreM <| Lean.collectAxioms n
  unless axs.all (fun a => a == ``propext || a == ``Classical.choice || a == ``Quot.sound) do
    throwError "{n} depends on axioms beyond the standard three: {axs}"
  logInfo m!"{n}: {axs}"

#assert_standard_axioms Classifier.mergeOne_keeps
#assert_standard_axioms Classifier.mergePaths_keeps
#assert_standard_axioms Classifier.mergePaths_of_mem
#assert_standard_axioms Classifier.merge_traversal
#assert_standard_axioms Classifier.merge_glob
#assert_standard_axioms Classifier.merge_unknown
#assert_standard_axioms Classifier.pathFacts_congr
#assert_standard_axioms Classifier.classify_eq
#assert_standard_axioms Classifier.classify_local
#assert_standard_axioms Classifier.fromCwd_congr
#assert_standard_axioms Classifier.bashArgv_congr
#assert_standard_axioms Classifier.hookTool_bash
#assert_standard_axioms Classifier.hookTool_not_bash
#assert_standard_axioms Classifier.hookCallIn_local
#assert_standard_axioms Classifier.inGrammar_of_quoted
#assert_standard_axioms Classifier.quoted_split
#assert_standard_axioms Classifier.splitPlainGo_outside
#assert_standard_axioms Classifier.splitPlainGo_chars
#assert_standard_axioms Classifier.splitPlain_words_chars
#assert_standard_axioms Classifier.splitPlain_outside
#assert_standard_axioms Classifier.bashArgv_operator
#assert_standard_axioms Classifier.bashArgv_outside
#assert_standard_axioms Classifier.bashArgv_tilde_brace
#assert_standard_axioms Classifier.classify_unknownCall
#assert_standard_axioms Classifier.hook_bash_unknown
#assert_standard_axioms Classifier.commandClass_read_only
#assert_standard_axioms Classifier.runPlan_keeps
#assert_standard_axioms Classifier.plan_commandClass
#assert_standard_axioms Classifier.classify_read_only
#assert_standard_axioms Classifier.privilege_unknown
#assert_standard_axioms Classifier.url_network
#assert_standard_axioms Classifier.workspace_program_mutating
#assert_standard_axioms Classifier.pathFacts_traversal
#assert_standard_axioms Classifier.pathFacts_glob
#assert_standard_axioms Classifier.classify_traversal
#assert_standard_axioms Classifier.classify_glob
#assert_standard_axioms Classifier.isGlob_of_char
#assert_standard_axioms Classifier.isTraversal_of_component
#assert_standard_axioms Classifier.path_tool_plan
#assert_standard_axioms Classifier.write_plan
#assert_standard_axioms Classifier.pathLike_mem
#assert_standard_axioms Classifier.runCall_plan
#assert_standard_axioms Classifier.run_command_plan
#assert_standard_axioms Classifier.killByPattern_cons
#assert_standard_axioms Classifier.kill_pkill
#assert_standard_axioms Classifier.kill_not_by_pid
#assert_standard_axioms Classifier.kill_xargs
#assert_standard_axioms Classifier.kill_wrapped
#assert_standard_axioms Classifier.argKills_word
#assert_standard_axioms Classifier.argKills_inner
#assert_standard_axioms Classifier.innerKill_of
#assert_standard_axioms Classifier.killArgsByPid_sound
#assert_standard_axioms Classifier.classify_kill
#assert_standard_axioms Classifier.kill_only_run_command
#assert_standard_axioms Classifier.git_unsafe_unknown
#assert_standard_axioms Classifier.git_push_remote
#assert_standard_axioms Classifier.classify_unknown_tool
#assert_standard_axioms Classifier.hook_unknown_tool
#assert_standard_axioms Classifier.mcp_unknown_tool
#assert_standard_axioms Classifier.reading_fields
#assert_standard_axioms Classifier.field_category
#assert_standard_axioms Classifier.field_bool
#assert_standard_axioms Classifier.field_other
#assert_standard_axioms Classifier.accept_fits
#assert_standard_axioms Classifier.firstRefused_fits
#assert_standard_axioms Classifier.boundary_accepts_every_reading
#assert_standard_axioms Classifier.decide_never_contract
