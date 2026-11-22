-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Net
/-!
# Zones: the reading field `zone_reach` and the policies that ask about it

A call that changes files names paths. The classifier asks an information point (`zone : Str → Zone`, in Python
`Config.zones`, prismpath/agent/zones.py) one question per path the syntactic check passes, and reads

* `none` for a call that changes no file;
* for a call that changes files (the write and delete tools and a mutating command): `protected` when any answer is
  `protected`, else `unknown` when any answer is `unknown`, else `none`; and `unknown` when it names no path the check
  passes.

The point is an observation, like the disk, and is outside the proof: what is proved is proved for every function
`zone` can be. The answer of Context Cloud and the zone file that lists the protected names are the adapter's
(prismpath/agent/zones.py).

What is proved, in claims kept apart:

* `zoneOf_none_iff`: a change reads `none` exactly when it names a path and the point answered `none` for every one
  of them. So `unknown` is what a missing, failing or silent point gives (`zoneOf_absent`), and one `protected`
  answer makes the change `protected` (`zoneOf_protected`).
* `zoneSafe p` (computed over the whole space of readings by the oracle's `--policy` mode, `zone_asked`): under the
  policy `p`, no change that reads `protected` or `unknown` is allowed. `zone_not_allowed` turns it into a theorem
  about every reading, and `allowed_change_every_path_none` into one about every call: **under a `zoneSafe` policy a
  change that is allowed names at least one path, and the point answered `none` for each**. `absent_point_not_allowed`
  and `protected_not_allowed` state the two cases that matter: with no point (every answer `unknown`) no change is
  allowed, and a change to a path the point calls protected is not allowed whatever its other paths say.
* `classifyZ_only_zone`: `classifyZ` differs from `classifyD` in the field `zone_reach` only, so every earlier
  theorem about the other fields (the control and network refusals, the scan) holds for it.

What is not proved: that the point tells the truth (that a file it calls `none` cannot reach protected code), that
the owner's zone file lists every name that matters, and that a change to code outside every function (module level
code) is seen at all.
-/

namespace Classifier

open Core (J)

/-- A reading that changes files in the way the zone fact reads: the write and delete tools, and a `run_command`
that reads mutating. A local git change is not one (it names no path to ask about). -/
def changing (r : Reading) : Bool :=
  r.tool == .write_file || r.tool == .delete_path || (r.tool == .run_command && r.commandClass == .mutating)

/-- The answers of the point for each path, joined: protected beats unknown beats none. -/
def zoneJoin (xs : List Zone) : Zone :=
  if xs.contains .protectedZ then .protectedZ else if xs.contains .unknown then .unknown else .none

/-- `classifier.zone_reach` of a call whose reading is `r` and whose planned paths are `ps`. -/
def zoneOf (zone : Str → Zone) (r : Reading) (ps : List Str) : Zone :=
  if changing r then
    if (ps.filter pathOk).isEmpty then .unknown else zoneJoin ((ps.filter pathOk).map zone)
  else .none

/-- `classifier.classify` with the zone fact: the reading of `classifyD` and `zone_reach` besides. -/
def classifyZ (zone : Str → Zone) (disk : Str → Disk) (remotes : List Str) (call : J) : Reading :=
  let r := classifyD disk remotes call
  if r.tool == .unknown then r else { r with zoneReach := zoneOf zone r (plan remotes call).2 }

/-- The paths at which `classifyZ` asks the point (after the disk facts are known). -/
def zoneQueries (disk : Str → Disk) (remotes : List Str) (call : J) : List Str :=
  let r := classifyD disk remotes call
  if r.tool == .unknown || !changing r then [] else (plan remotes call).2.filter pathOk

/-- `claude_code.hook_reading` with the zone fact: a call the mapping reads (not the unknown call) is classified
with `classifyZ`, and the unknown call keeps the reading of `hookReading` (the scan's or the unknown reading, whose
`zone_reach` is `none`). -/
def hookReadingZ (zone : Str → Zone) (d : HookDisk) (disk : Str → Disk) (hook : J) (projectDir : Option Str)
    (procCwd : Str) : Reading :=
  let call := (hookCall d hook projectDir procCwd).1
  if isUnknownCall call then hookReading d disk hook projectDir procCwd else classifyZ zone disk [] call

/-! ## What `zone_reach` reads -/

theorem zoneJoin_eq_none {xs : List Zone} : zoneJoin xs = .none ↔ ∀ x ∈ xs, x = .none := by
  unfold zoneJoin
  constructor
  · intro h x hx
    cases x with
    | none => rfl
    | protectedZ => have hm : Zone.protectedZ ∈ xs := hx; simp [hm] at h
    | unknown =>
      have hm : Zone.unknown ∈ xs := hx
      by_cases h1 : Zone.protectedZ ∈ xs <;> simp [h1, hm] at h
  · intro h
    have h1 : Zone.protectedZ ∉ xs := fun m => by have := h _ m; simp at this
    have h2 : Zone.unknown ∉ xs := fun m => by have := h _ m; simp at this
    simp [h1, h2]

theorem zoneJoin_protected {xs : List Zone} {x : Zone} (hx : x ∈ xs) (h : x = .protectedZ) :
    zoneJoin xs = .protectedZ := by
  have hm : Zone.protectedZ ∈ xs := h ▸ hx
  simp [zoneJoin, hm]

/-- **A change reads `none` exactly when it names a path the check passes and the point answered `none` for every
such path.** -/
theorem zoneOf_none_iff {zone : Str → Zone} {r : Reading} {ps : List Str} (hc : changing r = true) :
    zoneOf zone r ps = .none ↔ (ps.filter pathOk ≠ [] ∧ ∀ q ∈ ps.filter pathOk, zone q = .none) := by
  unfold zoneOf
  simp only [hc, if_true]
  by_cases he : (ps.filter pathOk).isEmpty = true
  · have : ps.filter pathOk = [] := List.isEmpty_iff.mp he
    simp [he, this]
  · have hne : ps.filter pathOk ≠ [] := fun h => he (by simp [h])
    simp only [he, Bool.false_eq_true, if_false, zoneJoin_eq_none, List.mem_map]
    constructor
    · intro h; exact ⟨hne, fun q hq => h _ ⟨q, hq, rfl⟩⟩
    · intro ⟨_, h⟩ x ⟨q, hq, hx⟩; rw [← hx]; exact h q hq

theorem zoneOf_not_changing (zone : Str → Zone) (r : Reading) (ps : List Str) (h : changing r = false) :
    zoneOf zone r ps = .none := by
  simp [zoneOf, h]

/-- **With no point (every answer `unknown`), a change reads `unknown`.** -/
theorem zoneOf_absent (r : Reading) (ps : List Str) (hc : changing r = true) :
    zoneOf (fun _ => .unknown) r ps = .unknown := by
  unfold zoneOf
  simp only [hc, if_true]
  by_cases he : (ps.filter pathOk).isEmpty = true
  · simp [he]
  · have hne : ps.filter pathOk ≠ [] := fun h => he (by simp [h])
    obtain ⟨q, hq⟩ := List.exists_mem_of_ne_nil _ hne
    have hm : Zone.unknown ∈ (ps.filter pathOk).map (fun _ => Zone.unknown) := List.mem_map.mpr ⟨q, hq, rfl⟩
    have hp : Zone.protectedZ ∉ (ps.filter pathOk).map (fun _ => Zone.unknown) := by simp
    simp [he, zoneJoin, hm, hp]

/-- **One `protected` answer makes the change `protected`, whatever the other paths say.** -/
theorem zoneOf_protected {zone : Str → Zone} {r : Reading} {ps : List Str} (hc : changing r = true) {q : Str}
    (hq : q ∈ ps.filter pathOk) (h : zone q = .protectedZ) : zoneOf zone r ps = .protectedZ := by
  unfold zoneOf
  simp only [hc, if_true]
  have hne : (ps.filter pathOk).isEmpty = false := by
    cases hl : ps.filter pathOk with
    | nil => rw [hl] at hq; simp at hq
    | cons _ _ => rfl
  simp only [hne, Bool.false_eq_true, if_false]
  exact zoneJoin_protected (x := zone q) (List.mem_map.mpr ⟨q, hq, rfl⟩) h

theorem changing_tool (r : Reading) (h : changing r = true) : r.tool ≠ .unknown := by
  intro ht
  simp [changing, ht] at h

/-- `classifyZ` differs from `classifyD` in `zone_reach` only. -/
theorem classifyZ_only_zone (zone : Str → Zone) (disk : Str → Disk) (remotes : List Str) (call : J) :
    { classifyZ zone disk remotes call with zoneReach := (classifyD disk remotes call).zoneReach } =
      classifyD disk remotes call := by
  unfold classifyZ
  dsimp only
  generalize classifyD disk remotes call = r
  by_cases h : (r.tool == Tool.unknown) = true
  · simp only [h, if_true]
  · simp only [h, if_false]; cases r; rfl

/-- The reading `classifyZ` gives a change. -/
theorem classifyZ_changing {zone : Str → Zone} {disk : Str → Disk} {remotes : List Str} {call : J}
    (hc : changing (classifyD disk remotes call) = true) :
    changing (classifyZ zone disk remotes call) = true ∧
    (classifyZ zone disk remotes call).zoneReach =
      zoneOf zone (classifyD disk remotes call) (plan remotes call).2 := by
  have ht := changing_tool _ hc
  have hu : ((classifyD disk remotes call).tool == .unknown) = false := by simpa using ht
  unfold classifyZ
  simp only [hu, Bool.false_eq_true, if_false]
  exact ⟨by simpa [changing] using hc, by simp⟩

/-! ## The policies -/

/-- A reading the zone rule must not let through: a change that reads `protected` or `unknown`. -/
def zoneBad (r : Reading) : Bool := changing r && r.zoneReach != .none

/-- Under `p`, no reading that `zoneBad` holds of is allowed. -/
def zoneSafe (p : Core.Checked) : Bool :=
  allTools.all fun t => allScopes.all fun s => allCmds.all fun c => allGitOps.all fun g =>
  allRemotes.all fun rc => allNetDests.all fun nd => allProcClasses.all fun pc => allZones.all fun zr =>
  bools.all fun k => bools.all fun tc => bools.all fun ctl => bools.all fun gl => bools.all fun tr =>
  bools.all fun sy =>
    let r : Reading :=
      { tool := t, pathScope := s, pathInToolchain := tc, pathControl := ctl, pathGlob := gl, pathTraversal := tr,
        pathSymlink := sy, commandClass := c, killByPattern := k, gitOp := g, remoteClass := rc, netDest := nd,
        procClass := pc, zoneReach := zr }
    !zoneBad r || !isAllow (Core.decideReading p (.ok r.json))

/-- **Under a `zoneSafe` policy, a change that reads `protected` or `unknown` is not allowed** (it is asked about or
refused). -/
theorem zone_not_allowed {p : Core.Checked} (hp : zoneSafe p = true) {r : Reading} (hb : zoneBad r = true) :
    isAllow (Core.decideReading p (.ok r.json)) = false := by
  simp only [zoneSafe, List.all_eq_true] at hp
  have := hp r.tool (tool_mem _) r.pathScope (scope_mem _) r.commandClass (cmd_mem _) r.gitOp (gitop_mem _)
    r.remoteClass (remote_mem _) r.netDest (netdest_mem _) r.procClass (procclass_mem _) r.zoneReach (zone_mem _)
    r.killByPattern (bool_mem _) r.pathInToolchain (bool_mem _) r.pathControl (bool_mem _) r.pathGlob (bool_mem _)
    r.pathTraversal (bool_mem _) r.pathSymlink (bool_mem _)
  cases r
  simp_all

/-- **An allowed change reads `none`: it names a path, and the point answered `none` for every path it names.** -/
theorem allowed_change_every_path_none {p : Core.Checked} (hp : zoneSafe p = true) (zone : Str → Zone)
    (disk : Str → Disk) (remotes : List Str) (call : J)
    (hc : changing (classifyD disk remotes call) = true)
    (ha : isAllow (Core.decideReading p (.ok (classifyZ zone disk remotes call).json)) = true) :
    (plan remotes call).2.filter pathOk ≠ [] ∧ ∀ q ∈ (plan remotes call).2.filter pathOk, zone q = .none := by
  obtain ⟨hcz, hz⟩ := classifyZ_changing (zone := zone) hc
  have hnb : zoneBad (classifyZ zone disk remotes call) = false := by
    cases hb : zoneBad (classifyZ zone disk remotes call)
    · rfl
    · have := zone_not_allowed hp hb
      simp_all
  have hnone : (classifyZ zone disk remotes call).zoneReach = .none := by
    simp only [zoneBad, hcz, Bool.true_and, bne_iff_ne, ne_eq, Bool.not_eq_false', decide_not,
      Bool.not_eq_true'] at hnb
    simpa using hnb
  rw [hz] at hnone
  exact (zoneOf_none_iff hc).mp hnone

/-- **With no information point, no change is allowed under a `zoneSafe` policy.** -/
theorem absent_point_not_allowed {p : Core.Checked} (hp : zoneSafe p = true) (disk : Str → Disk)
    (remotes : List Str) (call : J) (hc : changing (classifyD disk remotes call) = true) :
    isAllow (Core.decideReading p (.ok (classifyZ (fun _ => .unknown) disk remotes call).json)) = false := by
  obtain ⟨hcz, hz⟩ := classifyZ_changing (zone := fun _ => .unknown) hc
  have hr := zoneOf_absent (classifyD disk remotes call) (plan remotes call).2 hc
  apply zone_not_allowed hp
  simp [zoneBad, hcz, hz, hr]

/-- **A change to a path the point calls protected is not allowed under a `zoneSafe` policy**, whatever the point
says of its other paths. -/
theorem protected_not_allowed {p : Core.Checked} (hp : zoneSafe p = true) (zone : Str → Zone)
    (disk : Str → Disk) (remotes : List Str) (call : J) (hc : changing (classifyD disk remotes call) = true)
    {q : Str} (hq : q ∈ (plan remotes call).2.filter pathOk) (h : zone q = .protectedZ) :
    isAllow (Core.decideReading p (.ok (classifyZ zone disk remotes call).json)) = false := by
  obtain ⟨hcz, hz⟩ := classifyZ_changing (zone := zone) hc
  have hr := zoneOf_protected (zone := zone) hc hq h
  apply zone_not_allowed hp
  simp [zoneBad, hcz, hz, hr]

/-- The hook's reading for a call the mapping reads is `classifyZ`'s. -/
theorem hookReadingZ_known (zone : Str → Zone) (d : HookDisk) (disk : Str → Disk) (hook : J)
    (pd : Option Str) (pc : Str) (h : isUnknownCall (hookCall d hook pd pc).1 = false) :
    hookReadingZ zone d disk hook pd pc = classifyZ zone disk [] (hookCall d hook pd pc).1 := by
  simp [hookReadingZ, h]

/-- The hook's reading for the unknown call is `hookReading`'s: the scan's readings keep `zone_reach` `none`, so the
theorems about them stand. -/
theorem hookReadingZ_unknown (zone : Str → Zone) (d : HookDisk) (disk : Str → Disk) (hook : J)
    (pd : Option Str) (pc : Str) (h : isUnknownCall (hookCall d hook pd pc).1 = true) :
    hookReadingZ zone d disk hook pd pc = hookReading d disk hook pd pc := by
  simp [hookReadingZ, h]

end Classifier
