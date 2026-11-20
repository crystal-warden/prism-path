-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Scan
import Classifier.Theorems
/-!
# The agent's control files

The governed agent must not rewrite its own controls: the hook that governs it (`.claude/settings.json`, its local
overrides, `.claude/hooks/`), its MCP configuration (`.mcp.json`), and the program the installed hook runs. Which
paths those are is read off the disk, like a toolchain directory or a symbolic link (`classifier.disk_facts`): the
path, resolved or normalized, is a control file of the workspace as it is when the call is classified. So the model
takes it as an input, `Disk.control`, and what is proved holds for every value it can take.

* `classify_control`: a path the call names (`plan`'s list) that passes the syntactic check and that the disk says
  is a control file gives a reading with `path_control`.
* `isChange`: the readings that change something (a file written or deleted, a command that changes files, a local
  git write or mutation).
* `controlSafe p`: under the policy `p`, every reading with `path_control` that is a change is refused, computed over
  the whole space of such readings by the oracle's `--policy` mode (`control_refused`). All three shipped agent
  policies are `controlSafe`, and the harness requires it.
* `change_on_control_refused`: so a change that names a control file is refused, under such a policy, whatever the
  call (`write_control_refused`, `delete_control_refused` and `run_mutating_control_refused` state it for the
  write tool, the delete tool and a file changing command). A read of a control file is not a change and is
  decided as before.
-/

namespace Classifier

open Core (J)

/-- A reading that changes something: a file written or deleted, a command that changes files, or a local git
write or mutation. -/
def isChange (r : Reading) : Bool :=
  r.tool == .write_file || r.tool == .delete_path || r.commandClass == .mutating || r.gitOp == .local_write ||
  r.gitOp == .mutating

def allTools : List Tool := [.list_dir, .read_file, .write_file, .delete_path, .run_command, .git, .unknown]
def allScopes : List Scope := [.none, .workspace, .outside, .unknown]
def allCmds : List CmdClass := [.none, .read_only, .mutating, .network, .git, .unknown]
def allGitOps : List GitOp := [.none, .local_read, .local_write, .mutating, .push, .network, .unknown]
def allRemotes : List Remote := [.none, .allowed, .other]

/-- Every reading with `path_control`: one per combination of the other fields. -/
def controlSpace : List Reading :=
  allTools.flatMap fun t => allScopes.flatMap fun s => allCmds.flatMap fun c => allGitOps.flatMap fun g =>
  allRemotes.flatMap fun rc => bools.flatMap fun k => bools.flatMap fun tc => bools.flatMap fun gl =>
  bools.flatMap fun tr => bools.map fun sy =>
    { tool := t, pathScope := s, pathInToolchain := tc, pathControl := true, pathGlob := gl, pathTraversal := tr,
      pathSymlink := sy, commandClass := c, killByPattern := k, gitOp := g, remoteClass := rc }

/-- Under `p`, every change that names a control file is refused. -/
def controlSafe (p : Core.Checked) : Bool :=
  controlSpace.all (fun r => !isChange r || isRefusal (Core.decideReading p (.ok r.json)))

theorem tool_mem (t : Tool) : t ∈ allTools := by cases t <;> simp [allTools]
theorem scope_mem (t : Scope) : t ∈ allScopes := by cases t <;> simp [allScopes]
theorem cmd_mem (t : CmdClass) : t ∈ allCmds := by cases t <;> simp [allCmds]
theorem gitop_mem (t : GitOp) : t ∈ allGitOps := by cases t <;> simp [allGitOps]
theorem remote_mem (t : Remote) : t ∈ allRemotes := by cases t <;> simp [allRemotes]
theorem bool_mem (b : Bool) : b ∈ bools := by cases b <;> simp [bools]

theorem controlSpace_mem (r : Reading) (h : r.pathControl = true) : r ∈ controlSpace := by
  simp only [controlSpace, List.mem_flatMap, List.mem_map]
  refine ⟨r.tool, tool_mem _, r.pathScope, scope_mem _, r.commandClass, cmd_mem _, r.gitOp, gitop_mem _,
    r.remoteClass, remote_mem _, r.killByPattern, bool_mem _, r.pathInToolchain, bool_mem _, r.pathGlob, bool_mem _,
    r.pathTraversal, bool_mem _, r.pathSymlink, bool_mem _, ?_⟩
  cases r
  simp_all

/-- **Under a `controlSafe` policy, a change that reads `path_control` is refused.** -/
theorem control_refused {p : Core.Checked} (hp : controlSafe p = true) {r : Reading} (hc : r.pathControl = true)
    (hch : isChange r = true) : isRefusal (Core.decideReading p (.ok r.json)) = true := by
  have := List.all_eq_true.mp hp r (controlSpace_mem r hc)
  simpa [hch] using this

/-! ## The classifier reads a control path as control -/

theorem pathFacts_control (disk : Str → Disk) {raw : Str} (hok : pathOk raw = true) (h : (disk raw).control = true) :
    (pathFacts disk raw).control = true := by
  unfold pathFacts; simp [hok, h]

theorem merge_control {fs : List PathFacts} {f : PathFacts} (hf : f ∈ fs) (ht : f.control = true)
    (r : Reading) : (mergePaths r fs).pathControl = true :=
  mergePaths_of_mem (P := fun r => r.pathControl = true) (by intro r g h; simp [mergeOne, h])
    (by intro r; simp [mergeOne, ht]) hf

/-- **A control file reads as control.** Any path the call names that passes the syntactic check and that the disk
says is a control file gives a reading with `path_control`. -/
theorem classify_control {disk : Str → Disk} {remotes : List Str} {call : J} {p : Str}
    (hp : p ∈ (plan remotes call).2) (hok : pathOk p = true) (hc : (disk p).control = true) :
    (classify disk remotes call).pathControl = true := by
  rw [classify_eq]
  exact merge_control (List.mem_map_of_mem hp) (pathFacts_control disk hok hc) _

/-- **Under every `controlSafe` policy, a change that names a control file is refused**, whatever the call. -/
theorem change_on_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) {disk : Str → Disk}
    {remotes : List Str} {call : J} {p : Str} (hp : p ∈ (plan remotes call).2) (hok : pathOk p = true)
    (hc : (disk p).control = true) (hch : isChange (classify disk remotes call) = true) :
    isRefusal (Core.decideReading pol (.ok (classify disk remotes call).json)) = true :=
  control_refused hs (classify_control hp hok hc) hch

/-- The write tool is a change. -/
theorem write_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (p c : String) (hok : pathOk p.toList = true) (hc : (disk p.toList).control = true) :
    isRefusal (Core.decideReading pol
      (.ok (classify disk remotes
        (.obj [("tool", .str "write_file"), ("args", .obj [("path", .str p), ("content", .str c)])])).json)) = true := by
  have hp : p.toList ∈ (plan remotes
      (.obj [("tool", .str "write_file"), ("args", .obj [("path", .str p), ("content", .str c)])])).2 := by
    rw [write_plan]; simp
  refine change_on_control_refused hs hp hok hc ?_
  have := (mergePaths_keeps ({ tool := .write_file } : Reading) ((plan remotes
    (.obj [("tool", .str "write_file"), ("args", .obj [("path", .str p), ("content", .str c)])])).2.map (pathFacts disk))).1
  rw [classify_eq, write_plan]
  simp only [isChange]
  simp only [write_plan] at this
  rw [this]; simp

/-- The delete tool is a change. -/
theorem delete_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (p : String) (hok : pathOk p.toList = true) (hc : (disk p.toList).control = true) :
    isRefusal (Core.decideReading pol
      (.ok (classify disk remotes (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])])).json)) =
      true := by
  have hp : p.toList ∈ (plan remotes (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])])).2 := by
    rw [path_tool_plan remotes "delete_path" (by simp)]; simp
  refine change_on_control_refused hs hp hok hc ?_
  have := (mergePaths_keeps ({ tool := toolOf "delete_path" } : Reading) ((plan remotes
    (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])])).2.map (pathFacts disk))).1
  rw [classify_eq]
  simp only [path_tool_plan remotes "delete_path" (by simp)] at this ⊢
  simp only [isChange]
  rw [this]; simp [toolOf]

/-- A command that changes files, and is not git, is a change; so it is refused when an argument that is not an option
names a control file. -/
theorem run_mutating_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (xs : List J) (argv : List Str) (h : argvOf? xs = some argv)
    (hm : commandClass argv = .mutating) {a : Str} (ha : a ∈ argv.drop 1) (hd : startsWith a (lit "-") = false)
    (hok : pathOk a = true) (hc : (disk a).control = true) :
    isRefusal (Core.decideReading pol
      (.ok (classify disk remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).json)) =
      true := by
  have hg : commandClass argv ≠ .git := by rw [hm]; intro e; cases e
  have hp : a ∈ (plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).2 := by
    rw [runCall_plan remotes xs argv h]; exact run_command_plan hg ha hd
  refine change_on_control_refused hs hp hok hc ?_
  have hk := (mergePaths_keeps (plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).1
    ((plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).2.map (pathFacts disk))).2.1
  rw [classify_eq]
  simp only [isChange]
  rw [hk, runCall_plan remotes xs argv h, (runPlan_keeps remotes argv).2.1, hm]
  simp

end Classifier
