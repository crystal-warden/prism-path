-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Zone
import Classifier.ScanTheorems
/-!
# State across calls: the session fields and the policies that read them

A policy may read what the session already did. The decider (`prismpath/agent/session_state.py`) adds two fields to the
reading of a call, computed from the session's own journal, and the core decides the reading as it does any other, so
the core stays a pure function of (policy, reading):

* `session_protected_changes`: `none` or `some`, `some` once a receipt of the session is a change whose `zone_reach` was not
  `none` and was not refused;
* `session_shell_runs`: `none`, `few` or `many`, the receipts of the session that were not refused and read as a
  `run_command`, banded.

A state that cannot be read is the top, `Session.top` (`some`, `many`), never `Session.bot` (`none`, `none`). That is
the decider's, and it is outside the proof; what is proved is about every state the decider can give.

The classifier is unchanged: `Reading.json` is the reading without the fields, which is what every policy that does not
define them is decided on. `Reading.jsonS r s` is the same reading with the session fields of `s`, in canonical order,
which is what a policy that defines them is decided on.

What is proved, in claims kept apart:

* `sessionRefines p base` (computed over the whole space of readings and states by the oracle's `--session` mode,
  `session_restricts`): for every reading `r` and state `s`, the verdict of `p` on `r` with `s` is **at least as restrictive
  as the verdict of the stateless policy `base` on `r`** (allow, then ask, then refuse), **at most as restrictive as its own
  verdict at the top state**, and never a contract violation (the boundary accepts every reading with the fields).
  `session_restricts` states it for every `r` and `s`.
* Consequences, for every state: `session_refused` (what the base refuses, `p` refuses), `session_not_allowed` (what the
  base does not allow, `p` does not allow), `session_allowed_base_allowed` (what `p` allows, the base allows),
  `session_failsafe` (the top state is the most restrictive one, so an unreadable history never allows what a
  readable one would not), and `session_zone_not_allowed`, `session_control_refused`, `session_net_refused` and
  `session_scan_safe_reading`, the four safety theorems of the stateless policy carried to every state of the stateful one.

What is not proved: that the decider's state is the state of the journal (the derivation is Python, tested), and that the
journal holds every call the session made (a call the hook was never asked about leaves no receipt).
-/

namespace Classifier

open Core (J)

/-- Whether this session already made a change that reached the owner's zones (or whose reach was not known). -/
inductive SessionChanges where
  | none | some
  deriving DecidableEq, Repr, Inhabited

/-- How many shell commands the session ran, banded. -/
inductive SessionShell where
  | none | few | many
  deriving DecidableEq, Repr, Inhabited

structure Session where
  changes : SessionChanges
  shell : SessionShell
  deriving DecidableEq, Repr, Inhabited

def SessionChanges.name : SessionChanges → String
  | .none => "none" | .some => "some"
def SessionShell.name : SessionShell → String
  | .none => "none" | .few => "few" | .many => "many"

/-- The state of a session that has done nothing. -/
def Session.bot : Session := ⟨.none, .none⟩
/-- The most restrictive state, what a history that cannot be read reads as. -/
def Session.top : Session := ⟨.some, .many⟩

def allSessions : List Session :=
  [⟨.none, .none⟩, ⟨.none, .few⟩, ⟨.none, .many⟩, ⟨.some, .none⟩, ⟨.some, .few⟩, ⟨.some, .many⟩]

theorem session_mem (s : Session) : s ∈ allSessions := by
  obtain ⟨c, h⟩ := s
  cases c <;> cases h <;> simp [allSessions]

/-- The reading with the session fields, in the canonical order of the names: after `remote_class`, before `tool`. -/
def Reading.membersS (r : Reading) (s : Session) : List (String × J) :=
  r.members.take 13 ++
    [("session_protected_changes", .str s.changes.name), ("session_shell_runs", .str s.shell.name)] ++
    r.members.drop 13

def Reading.jsonS (r : Reading) (s : Session) : J := .obj (r.membersS s)

/-- How restrictive a verdict is: an allow, a question, a refusal. -/
def rank (v : Core.Verdict) : Nat := if isRefusal v then 2 else if isAllow v then 0 else 1

def isContract : Core.Verdict → Bool
  | .refuse (.contract _ _) => true
  | _ => false

theorem rank_le_two (v : Core.Verdict) : rank v ≤ 2 := by
  unfold rank; split <;> (try split) <;> omega

theorem rank_two_iff (v : Core.Verdict) : rank v = 2 ↔ isRefusal v = true := by
  unfold rank; split <;> (try split) <;> simp_all

theorem rank_zero_iff (v : Core.Verdict) : rank v = 0 ↔ isAllow v = true := by
  have key : isAllow v = true → isRefusal v = false := by
    cases v with
    | route t =>
      intro h
      simp only [isAllow, beq_iff_eq] at h
      subst h
      decide
    | refuse _ => intro h; simp [isAllow] at h
  unfold rank
  by_cases h1 : isRefusal v = true
  · have : isAllow v = false := by
      cases ha : isAllow v
      · rfl
      · have := key ha; simp_all
    simp [h1, this]
  · have h1' : isRefusal v = false := by simpa using h1
    simp [h1']

/-- **The policy `p`, which reads the session's state, only ever adds restriction to the stateless policy `base`.** Over every
reading of the classifier and every state: the verdict of `p` is at least as restrictive as `base`'s on the reading
without the fields, at most as restrictive as its own at the top state, and never a contract violation. -/
def sessionRefines (p base : Core.Checked) : Bool :=
  allTools.all fun t => allScopes.all fun s => allCmds.all fun c => allGitOps.all fun g =>
  allRemotes.all fun rc => allNetDests.all fun nd => allProcClasses.all fun pc => allZones.all fun zr =>
  bools.all fun k => bools.all fun tc => bools.all fun ctl => bools.all fun gl => bools.all fun tr =>
  bools.all fun sy =>
    let r : Reading :=
      { tool := t, pathScope := s, pathInToolchain := tc, pathControl := ctl, pathGlob := gl, pathTraversal := tr,
        pathSymlink := sy, commandClass := c, killByPattern := k, gitOp := g, remoteClass := rc, netDest := nd,
        procClass := pc, zoneReach := zr }
    let low := rank (Core.decideReading base (.ok r.json))
    let high := rank (Core.decideReading p (.ok (r.jsonS Session.top)))
    allSessions.all fun st =>
      let v := Core.decideReading p (.ok (r.jsonS st))
      decide (low ≤ rank v) && decide (rank v ≤ high) && !isContract v

theorem session_restricts {p base : Core.Checked} (hp : sessionRefines p base = true) (r : Reading) (s : Session) :
    rank (Core.decideReading base (.ok r.json)) ≤ rank (Core.decideReading p (.ok (r.jsonS s))) ∧
    rank (Core.decideReading p (.ok (r.jsonS s))) ≤ rank (Core.decideReading p (.ok (r.jsonS Session.top))) ∧
    isContract (Core.decideReading p (.ok (r.jsonS s))) = false := by
  simp only [sessionRefines, List.all_eq_true] at hp
  have := hp r.tool (tool_mem _) r.pathScope (scope_mem _) r.commandClass (cmd_mem _) r.gitOp (gitop_mem _)
    r.remoteClass (remote_mem _) r.netDest (netdest_mem _) r.procClass (procclass_mem _) r.zoneReach (zone_mem _)
    r.killByPattern (bool_mem _) r.pathInToolchain (bool_mem _) r.pathControl (bool_mem _) r.pathGlob (bool_mem _)
    r.pathTraversal (bool_mem _) r.pathSymlink (bool_mem _) s (session_mem s)
  cases r
  simp only [Bool.and_eq_true, decide_eq_true_eq, Bool.not_eq_true'] at this
  exact ⟨this.1.1, this.1.2, this.2⟩

/-- **What the stateless policy refuses, the stateful one refuses in every state.** -/
theorem session_refused {p base : Core.Checked} (hp : sessionRefines p base = true) {r : Reading} (s : Session)
    (h : isRefusal (Core.decideReading base (.ok r.json)) = true) :
    isRefusal (Core.decideReading p (.ok (r.jsonS s))) = true := by
  have h1 := (session_restricts hp r s).1
  have h2 := (rank_two_iff _).mpr h
  exact (rank_two_iff _).mp (by have := rank_le_two (Core.decideReading p (.ok (r.jsonS s))); omega)

/-- **What the stateless policy does not allow, the stateful one does not allow in any state.** -/
theorem session_not_allowed {p base : Core.Checked} (hp : sessionRefines p base = true) {r : Reading} (s : Session)
    (h : isAllow (Core.decideReading base (.ok r.json)) = false) :
    isAllow (Core.decideReading p (.ok (r.jsonS s))) = false := by
  have h1 := (session_restricts hp r s).1
  cases ha : isAllow (Core.decideReading p (.ok (r.jsonS s)))
  · rfl
  · exfalso
    have h0 := (rank_zero_iff _).mpr ha
    have hb : rank (Core.decideReading base (.ok r.json)) = 0 := by omega
    have := (rank_zero_iff _).mp hb
    rw [h] at this
    exact absurd this (by decide)

/-- **What the stateful policy allows in some state, the stateless policy allows.** -/
theorem session_allowed_base_allowed {p base : Core.Checked} (hp : sessionRefines p base = true) {r : Reading}
    (s : Session) (h : isAllow (Core.decideReading p (.ok (r.jsonS s))) = true) :
    isAllow (Core.decideReading base (.ok r.json)) = true := by
  cases hb : isAllow (Core.decideReading base (.ok r.json))
  · exfalso
    have := session_not_allowed hp s (r := r) hb
    rw [h] at this
    exact absurd this (by decide)
  · rfl

/-- **The top state is the most restrictive: a history that cannot be read never allows what a readable one would not.**
Whatever a call is decided as in some state, the decision at the top state is at least as restrictive. -/
theorem session_failsafe {p base : Core.Checked} (hp : sessionRefines p base = true) (r : Reading) (s : Session) :
    rank (Core.decideReading p (.ok (r.jsonS s))) ≤ rank (Core.decideReading p (.ok (r.jsonS Session.top))) :=
  (session_restricts hp r s).2.1

/-- A call allowed at the top state is allowed in every state. -/
theorem session_top_allowed {p base : Core.Checked} (hp : sessionRefines p base = true) (r : Reading) (s : Session)
    (h : isAllow (Core.decideReading p (.ok (r.jsonS Session.top))) = true) :
    isAllow (Core.decideReading p (.ok (r.jsonS s))) = true := by
  have h1 := session_failsafe hp r s
  have h0 := (rank_zero_iff _).mpr h
  exact (rank_zero_iff _).mp (by omega)

/-! ## The safety theorems of the stateless policy, in every state -/

/-- **Under a stateful policy that refines a `zoneSafe` policy, a change that reads `protected` or `unknown` is not allowed
in any state.** -/
theorem session_zone_not_allowed {p base : Core.Checked} (hp : sessionRefines p base = true) (hz : zoneSafe base = true)
    {r : Reading} (hb : zoneBad r = true) (s : Session) :
    isAllow (Core.decideReading p (.ok (r.jsonS s))) = false :=
  session_not_allowed hp s (zone_not_allowed hz hb)

/-- **Under a stateful policy that refines a `controlSafe` policy, a change that reads `path_control` is refused in every
state.** -/
theorem session_control_refused {p base : Core.Checked} (hp : sessionRefines p base = true) (hc : controlSafe base = true)
    {r : Reading} (hpc : r.pathControl = true) (hch : isChange r = true) (s : Session) :
    isRefusal (Core.decideReading p (.ok (r.jsonS s))) = true :=
  session_refused hp s (control_refused hc hpc hch)

/-- **A connection to anything but the model's API or an allowed host is refused in every state.** -/
theorem session_net_refused {p base : Core.Checked} (hp : sessionRefines p base = true) (hn : netSafe base = true)
    {r : Reading} (hb : netBad r = true) (s : Session) :
    isRefusal (Core.decideReading p (.ok (r.jsonS s))) = true :=
  session_refused hp s (net_refused hn hb)

/-- **A reading the hazard scan gives is never allowed in any state, and refused unless it is a push alone.** -/
theorem session_scan_safe_reading {p base : Core.Checked} (hp : sessionRefines p base = true) (hs : scanSafe base = true)
    {c ws : Str} {ctrl : Bool} {r : Reading} (h : scanReading c ws ctrl = some r) (s : Session) :
    isAllow (Core.decideReading p (.ok (r.jsonS s))) = false ∧
      (pushOnly r = true ∨ isRefusal (Core.decideReading p (.ok (r.jsonS s))) = true) := by
  obtain ⟨ha, hr⟩ := scan_safe_reading hs h
  refine ⟨session_not_allowed hp s ha, ?_⟩
  rcases hr with hpush | href
  · exact Or.inl hpush
  · exact Or.inr (session_refused hp s href)

/-- **An allowed change names a path and the point answered `none` for every path it names, in every state** (the
stateful policy allows nothing the stateless one does not). -/
theorem session_allowed_change_every_path_none {p base : Core.Checked} (hp : sessionRefines p base = true)
    (hz : zoneSafe base = true) (zone : Str → Zone) (disk : Str → Disk) (remotes : List Str) (call : J)
    (hc : changing (classifyD disk remotes call) = true) (s : Session)
    (ha : isAllow (Core.decideReading p (.ok ((classifyZ zone disk remotes call).jsonS s))) = true) :
    (plan remotes call).2.filter pathOk ≠ [] ∧ ∀ q ∈ (plan remotes call).2.filter pathOk, zone q = .none :=
  allowed_change_every_path_none hz zone disk remotes call hc (session_allowed_base_allowed hp s ha)

end Classifier
