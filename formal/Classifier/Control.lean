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

def allTools : List Tool := [.list_dir, .read_file, .write_file, .delete_path, .run_command, .git, .connect, .unknown]
def allScopes : List Scope := [.none, .workspace, .outside, .unknown]
def allCmds : List CmdClass := [.none, .read_only, .mutating, .network, .git, .unknown]
def allGitOps : List GitOp := [.none, .local_read, .local_write, .mutating, .push, .network, .unknown]
def allRemotes : List Remote := [.none, .allowed, .other]
def allNetDests : List NetDest := [.none, .model_api, .allowed_host, .other, .unknown]
def allProcClasses : List ProcClass := [.none, .single, .tree, .unknown]
def allZones : List Zone := [.none, .protectedZ, .unknown]

/-- Under `p`, every change that names a control file is refused: every reading with `path_control`, one per
combination of the other fields, decided by the core. -/
def controlSafe (p : Core.Checked) : Bool :=
  allTools.all fun t => allScopes.all fun s => allCmds.all fun c => allGitOps.all fun g =>
  allRemotes.all fun rc => allNetDests.all fun nd => allProcClasses.all fun pc => allZones.all fun zr =>
  bools.all fun k => bools.all fun tc => bools.all fun gl => bools.all fun tr => bools.all fun sy =>
    let r : Reading :=
      { tool := t, pathScope := s, pathInToolchain := tc, pathControl := true, pathGlob := gl, pathTraversal := tr,
        pathSymlink := sy, commandClass := c, killByPattern := k, gitOp := g, remoteClass := rc, netDest := nd,
        procClass := pc, zoneReach := zr }
    !isChange r || isRefusal (Core.decideReading p (.ok r.json))

theorem tool_mem (t : Tool) : t ∈ allTools := by cases t <;> simp [allTools]
theorem scope_mem (t : Scope) : t ∈ allScopes := by cases t <;> simp [allScopes]
theorem cmd_mem (t : CmdClass) : t ∈ allCmds := by cases t <;> simp [allCmds]
theorem gitop_mem (t : GitOp) : t ∈ allGitOps := by cases t <;> simp [allGitOps]
theorem remote_mem (t : Remote) : t ∈ allRemotes := by cases t <;> simp [allRemotes]
theorem netdest_mem (t : NetDest) : t ∈ allNetDests := by cases t <;> simp [allNetDests]
theorem procclass_mem (t : ProcClass) : t ∈ allProcClasses := by cases t <;> simp [allProcClasses]
theorem zone_mem (t : Zone) : t ∈ allZones := by cases t <;> simp [allZones]
theorem bool_mem (b : Bool) : b ∈ bools := by cases b <;> simp [bools]

/-- **Under a `controlSafe` policy, a change that reads `path_control` is refused.** -/
theorem control_refused {p : Core.Checked} (hp : controlSafe p = true) {r : Reading} (hc : r.pathControl = true)
    (hch : isChange r = true) : isRefusal (Core.decideReading p (.ok r.json)) = true := by
  simp only [controlSafe, List.all_eq_true] at hp
  have := hp r.tool (tool_mem _) r.pathScope (scope_mem _) r.commandClass (cmd_mem _) r.gitOp (gitop_mem _)
    r.remoteClass (remote_mem _) r.netDest (netdest_mem _) r.procClass (procclass_mem _) r.zoneReach (zone_mem _) r.killByPattern (bool_mem _)
    r.pathInToolchain (bool_mem _) r.pathGlob (bool_mem _) r.pathTraversal (bool_mem _) r.pathSymlink (bool_mem _)
  cases r
  simp_all

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

theorem isChange_classifyD (disk : Str → Disk) (remotes : List Str) (call : J) :
    isChange (classifyD disk remotes call) = isChange (classify disk remotes call) := rfl

theorem classifyD_control {disk : Str → Disk} {remotes : List Str} {call : J}
    (h : (classify disk remotes call).pathControl = true) : (classifyD disk remotes call).pathControl = true := by
  simp [classifyD, h]

/-- **A directory that a removal or a move names and that holds control files reads as control.** -/
theorem classify_holder {disk : Str → Disk} {remotes : List Str} {call : J} {p : Str}
    (hp : p ∈ destroyPaths remotes call) (hok : pathOk p = true) (hh : (disk p).holder = true) :
    (classifyD disk remotes call).pathControl = true := by
  simp only [classifyD, Bool.or_eq_true]
  exact Or.inr (List.any_eq_true.mpr ⟨p, hp, by simp [holderHit, hok, hh]⟩)

/-- **Under every `controlSafe` policy, a change that names a control file is refused**, whatever the call. -/
theorem change_on_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) {disk : Str → Disk}
    {remotes : List Str} {call : J} {p : Str} (hp : p ∈ (plan remotes call).2) (hok : pathOk p = true)
    (hc : (disk p).control = true) (hch : isChange (classify disk remotes call) = true) :
    isRefusal (Core.decideReading pol (.ok (classifyD disk remotes call).json)) = true :=
  control_refused hs (classifyD_control (classify_control hp hok hc)) (by rw [isChange_classifyD]; exact hch)

/-- The write tool is a change. -/
theorem write_control_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (p c : String) (hok : pathOk p.toList = true) (hc : (disk p.toList).control = true) :
    isRefusal (Core.decideReading pol
      (.ok (classifyD disk remotes
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
      (.ok (classifyD disk remotes (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])])).json)) =
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
      (.ok (classifyD disk remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).json)) =
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

/-! ## Removing or moving the root or a directory that holds control files -/

/-- **Under every `controlSafe` policy, a change that removes or moves a holder is refused.** -/
theorem change_on_holder_refused {pol : Core.Checked} (hs : controlSafe pol = true) {disk : Str → Disk}
    {remotes : List Str} {call : J} {p : Str} (hp : p ∈ destroyPaths remotes call) (hok : pathOk p = true)
    (hh : (disk p).holder = true) (hch : isChange (classify disk remotes call) = true) :
    isRefusal (Core.decideReading pol (.ok (classifyD disk remotes call).json)) = true :=
  control_refused hs (classify_holder hp hok hh) (by rw [isChange_classifyD]; exact hch)

/-- The delete tool naming the root or a directory that holds control files is refused. -/
theorem delete_holder_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (p : String) (hok : pathOk p.toList = true) (hh : (disk p.toList).holder = true) :
    isRefusal (Core.decideReading pol
      (.ok (classifyD disk remotes (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])])).json)) =
      true := by
  have hplan := path_tool_plan remotes "delete_path" (by simp) p
  have hd : p.toList ∈ destroyPaths remotes (.obj [("tool", .str "delete_path"), ("args", .obj [("path", .str p)])]) := by
    simp only [destroyPaths, hplan, toolOf]; simp
  refine change_on_holder_refused hs hd hok hh ?_
  rw [classify_eq, hplan]
  simp [isChange, mergePaths_keeps, toolOf]

/-- `rm` and `rmdir` destroy every path they name. -/
theorem destroyArgs_rm {first : Str} {args : List Str} {base : Str} (hb : program first = some base)
    (hr : base = lit "rm" ∨ base = lit "rmdir") {a : Str} (ha : a ∈ pathLike false args) :
    a ∈ destroyArgs (first :: args) := by
  simp only [destroyArgs, hb]
  rcases hr with rfl | rfl <;> simpa using ha

/-- A file changing command whose argv destroys a path that is the root or holds control files is refused. -/
theorem run_destroy_holder_refused {pol : Core.Checked} (hs : controlSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (xs : List J) (argv : List Str) (h : argvOf? xs = some argv)
    (hm : commandClass argv = .mutating) {a : Str} (ha : a ∈ destroyArgs argv) (hok : pathOk a = true)
    (hh : (disk a).holder = true) :
    isRefusal (Core.decideReading pol
      (.ok (classifyD disk remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).json)) =
      true := by
  have hpl := runCall_plan remotes xs argv h
  have hd : a ∈ destroyPaths remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])]) := by
    have ht := (runPlan_keeps remotes argv).1
    simp only [destroyPaths, hpl, ht]
    simp [get?, Core.field?, h, ha]
  refine change_on_holder_refused hs hd hok hh ?_
  have hk := (mergePaths_keeps (plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).1
    ((plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).2.map (pathFacts disk))).2.1
  rw [classify_eq]
  simp only [isChange]
  rw [hk, hpl, (runPlan_keeps remotes argv).2.1, hm]
  simp

end Classifier
