-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Scan
/-!
# The hazard scan's theorems

* Each detection rule, as stated: `scan_kill`, `scan_network`, `scan_outside`, `scan_traversal`, `scan_toolchain`,
  `scan_glob`, `scan_long`, `scan_git`, with the evidence lemmas (`killEvidence_of_word`,
  `networkEvidence_of_word`, `networkEvidence_of_url`, `installerEvidence_of`, `outsideEvidence_of_token`, ...) and
  the git lemmas (`gitScan_ge`, `gitOpOf_unsafe`, `gitOpOf_push`, `gitOpOf_network`, `gitOpOf_mutating`,
  `gitOpOf_reset_hard`, `gitOpOf_unknown_sub`).
* The label: a network word only inside path tokens is no network evidence (`network_word_in_path_only`).
* No evidence, no change: `scan_none`, `hookReading_unchanged`.
* The scan never allows and, but for a push alone, only refuses: `scanReading_mem`, `scan_safe_reading`,
  `hookReading_only_adds_refusals`.
-/

namespace Classifier

open Core (J)

/-- The evidence of a stripped text, in the order `scanOf` takes it. -/
def evidence (ws t : Str) : Bool × Bool × Bool × Bool × Bool × Bool × Bool × GitOp :=
  (killEvidence t, networkEvidence ws t, outsideEvidence ws t, traversalEvidence t, toolchainEvidence t,
   globEvidence t, longEvidence t, gitScan (tokens t))

theorem scanReading_eq (c ws : Str) : scanReading c ws =
    let t := strip c
    if fires (killEvidence t) (networkEvidence ws t) (outsideEvidence ws t) (traversalEvidence t) (toolchainEvidence t)
        (globEvidence t) (longEvidence t) (gitScan (tokens t)) then
      some (scanOf (killEvidence t) (networkEvidence ws t) (outsideEvidence ws t) (traversalEvidence t)
        (toolchainEvidence t) (globEvidence t) (longEvidence t) (gitScan (tokens t)))
    else none := rfl

theorem scan_fires {c ws : Str} (h : fires (killEvidence (strip c)) (networkEvidence ws (strip c))
      (outsideEvidence ws (strip c)) (traversalEvidence (strip c)) (toolchainEvidence (strip c)) (globEvidence (strip c))
      (longEvidence (strip c)) (gitScan (tokens (strip c))) = true) :
    scanReading c ws = some (scanOf (killEvidence (strip c)) (networkEvidence ws (strip c)) (outsideEvidence ws (strip c))
      (traversalEvidence (strip c)) (toolchainEvidence (strip c)) (globEvidence (strip c)) (longEvidence (strip c))
      (gitScan (tokens (strip c)))) := by
  rw [scanReading_eq]; simp only [h, if_true]

/-- **No evidence, no change**: the scan gives nothing. -/
theorem scan_none {c ws : Str} (h : fires (killEvidence (strip c)) (networkEvidence ws (strip c))
      (outsideEvidence ws (strip c)) (traversalEvidence (strip c)) (toolchainEvidence (strip c)) (globEvidence (strip c))
      (longEvidence (strip c)) (gitScan (tokens (strip c))) = false) : scanReading c ws = none := by
  rw [scanReading_eq]; simp only [h, Bool.false_eq_true, if_false]

/-! ## The detection rules -/

theorem killEvidence_of_word {t w : Str} (hw : w ∈ asciiWords t) (hk : w = lit "pkill" ∨ w = lit "killall" ∨ w = lit "kill") :
    killEvidence t = true :=
  List.any_eq_true.mpr ⟨w, hw, by rcases hk with rfl | rfl | rfl <;> decide⟩

/-- A network word counts in a token that gives no path evidence. -/
theorem networkEvidence_of_word {ws t tok w : Str} (ht : tok ∈ tokens t) (hp : pathToken ws tok = false)
    (hw : w ∈ asciiWords tok) (hn : NETWORK.contains w = true) : networkEvidence ws t = true := by
  have : networkWordEvidence ws t = true :=
    List.any_eq_true.mpr ⟨tok, ht, by simp only [hp, Bool.not_false, Bool.true_and]; exact List.any_eq_true.mpr ⟨w, hw, hn⟩⟩
  simp [networkEvidence, this]

theorem networkEvidence_of_url {ws t : Str} (hu : hasURL t = true) : networkEvidence ws t = true := by
  simp [networkEvidence, hu]

/-- An installer token followed, in any later token, by one of its fetch words. -/
theorem installerEvidence_of : ∀ {toks : List Str} {pre : List Str} {i : Str} {rest : List Str},
    toks = pre ++ i :: rest → installerAt i rest = true → installerEvidence toks = true
  | _, [], i, rest, rfl, h => by simp [installerEvidence, h]
  | _, p :: pre, i, rest, rfl, h => by
    simp only [List.cons_append, installerEvidence, Bool.or_eq_true]
    exact Or.inr (installerEvidence_of rfl h)

theorem networkEvidence_of_installer {ws t : Str} (h : installerEvidence (tokens t) = true) :
    networkEvidence ws t = true := by
  simp [networkEvidence, h]

/-- **The label.** When every token holding a network word gives path evidence, and there is no URL scheme and no
installer, there is no network evidence: `cat ~/.ssh/id_rsa` refuses as outside the workspace, not as network. -/
theorem network_word_in_path_only {ws t : Str}
    (hp : ∀ tok ∈ tokens t, (asciiWords tok).any (fun w => NETWORK.contains w) = true → pathToken ws tok = true)
    (hu : hasURL t = false) (hi : installerEvidence (tokens t) = false) : networkEvidence ws t = false := by
  have : networkWordEvidence ws t = false := by
    simp only [networkWordEvidence, List.any_eq_false, Bool.and_eq_true, Bool.not_eq_true', not_and]
    intro tok htok hnp hw
    have := hp tok htok hw
    simp_all
  simp [networkEvidence, this, hu, hi]

theorem outsideEvidence_of_token {ws t tok : Str} (ht : tok ∈ tokens t) (ho : outsideToken ws tok = true) :
    outsideEvidence ws t = true := List.any_eq_true.mpr ⟨tok, ht, ho⟩

theorem outsideToken_abs {ws tok : Str} (hs : startsWith tok (lit "/") = true) (hne : tok ≠ ws)
    (hb : startsWith tok (ws ++ ['/']) = false) : outsideToken ws tok = true := by
  have : (tok == ws) = false := by simpa using hne
  simp [outsideToken, hs, this, hb]

theorem outsideToken_home {ws tok : Str} (hs : startsWith tok (lit "~") = true) : outsideToken ws tok = true := by
  simp [outsideToken, hs]

theorem traversalEvidence_of_token {t tok : Str} (ht : tok ∈ tokens t) (hd : lit ".." ∈ splitSlash tok) :
    traversalEvidence t = true := List.any_eq_true.mpr ⟨tok, ht, by simpa [traversalToken] using hd⟩

theorem toolchainEvidence_of_token {t tok : Str} (ht : tok ∈ tokens t) (hd : lit ".toolchain" ∈ splitSlash tok) :
    toolchainEvidence t = true := List.any_eq_true.mpr ⟨tok, ht, by simpa [toolchainToken] using hd⟩

theorem globEvidence_of_char {t tok : Str} {c : Char} (ht : tok ∈ tokens t) (hc : c ∈ tok) (hg : isScanGlobChar c = true) :
    globEvidence t = true := List.any_eq_true.mpr ⟨tok, ht, List.any_eq_true.mpr ⟨c, hc, hg⟩⟩

theorem longEvidence_of_token {t tok : Str} (ht : tok ∈ tokens t) (hl : tok.length > MAX_PATH ∨ '\x00' ∈ tok) :
    longEvidence t = true :=
  List.any_eq_true.mpr ⟨tok, ht, by rcases hl with h | h <;> simp [longToken, h]⟩

/-! ## git -/

theorem maxOp_ge_left (a b : GitOp) : a.rank ≤ (maxOp a b).rank := by
  unfold maxOp; split <;> omega

theorem maxOp_ge_right (a b : GitOp) : b.rank ≤ (maxOp a b).rank := by
  unfold maxOp; split <;> omega

/-- Every `git` token's reading is at most as severe as the scan's. -/
theorem gitScan_ge : ∀ {toks pre rest : List Str} {g : Str}, toks = pre ++ g :: rest → basename g = lit "git" →
    (gitOpOf rest).rank ≤ (gitScan toks).rank
  | _, [], rest, g, rfl, hg => by
    simp only [List.nil_append, gitScan, hg, beq_self_eq_true, if_true]
    exact maxOp_ge_left _ _
  | _, p :: pre, rest, g, rfl, hg => by
    simp only [List.cons_append, gitScan]
    exact Nat.le_trans (gitScan_ge rfl hg) (maxOp_ge_right _ _)

theorem gitOpOf_unsafe {rest : List Str} (h : rest.any unsafeOption = true) : gitOpOf rest = .unknown := by
  simp [gitOpOf, h]

theorem gitOpOf_sub {rest : List Str} {s : Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some s) :
    gitOpOf rest = if s == lit "push" then .push
      else if GIT_NETWORK.contains s then .network
      else if GIT_MUTATING.contains s then .mutating
      else if s == lit "reset" then (if rest.contains (lit "--hard") then .mutating else .none)
      else if s == lit "remote" then
        (if ((rest.dropWhile (· != s)).drop 1).all (fun a => a == lit "-v" || a == lit "--verbose") then .none
         else .unknown)
      else if GIT_LOCAL_READ.contains s || GIT_LOCAL_WRITE.contains s then .none
      else .unknown := by
  simp only [gitOpOf, hu, Bool.false_eq_true, if_false, hs]

theorem gitOpOf_push {rest : List Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some (lit "push")) : gitOpOf rest = .push := by
  rw [gitOpOf_sub hu hs]; simp

theorem gitOpOf_network {rest : List Str} {s : Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some s) (hn : GIT_NETWORK.contains s = true) :
    gitOpOf rest = .network := by
  rw [gitOpOf_sub hu hs]
  have : (s == lit "push") = false := by
    cases h : (s == lit "push")
    · rfl
    · rw [beq_iff_eq.mp h] at hn; exact absurd hn (by decide)
  simp only [this, Bool.false_eq_true, if_false, hn, if_true]

theorem gitOpOf_mutating {rest : List Str} {s : Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some s) (hm : GIT_MUTATING.contains s = true) :
    gitOpOf rest = .mutating := by
  rw [gitOpOf_sub hu hs]
  have h1 : (s == lit "push") = false := by
    cases h : (s == lit "push")
    · rfl
    · rw [beq_iff_eq.mp h] at hm; exact absurd hm (by decide)
  have h2 : GIT_NETWORK.contains s = false := by
    cases h : GIT_NETWORK.contains s
    · rfl
    · exfalso
      have hm' := List.elem_iff.mp hm; have h' := List.elem_iff.mp h
      simp only [GIT_MUTATING, GIT_NETWORK, wordsOf, List.map, List.mem_cons, List.not_mem_nil, or_false] at hm' h'
      rcases h' with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
        rcases hm' with h | h | h | h | h | h | h | h | h | h | h | h | h | h <;> exact absurd h (by decide)
  simp only [h1, h2, Bool.false_eq_true, if_false, hm, if_true]

theorem gitOpOf_reset_hard {rest : List Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some (lit "reset")) (hh : lit "--hard" ∈ rest) :
    gitOpOf rest = .mutating := by
  rw [gitOpOf_sub hu hs]
  have : rest.contains (lit "--hard") = true := List.elem_iff.mpr hh
  have e1 : (lit "reset" == lit "push") = false := by decide
  have e2 : GIT_NETWORK.contains (lit "reset") = false := by decide
  have e3 : GIT_MUTATING.contains (lit "reset") = false := by decide
  simp only [e1, e2, e3, Bool.false_eq_true, if_false, beq_self_eq_true, if_true, this]

/-- A subcommand the classifier does not know is unknown. -/
theorem gitOpOf_unknown_sub {rest : List Str} {s : Str} (hu : rest.any unsafeOption = false)
    (hs : rest.find? (fun a => !startsWith a (lit "-")) = some s)
    (hk : s ∉ [lit "push", lit "reset", lit "remote"]) (hn : GIT_NETWORK.contains s = false)
    (hm : GIT_MUTATING.contains s = false) (hr : GIT_LOCAL_READ.contains s = false)
    (hw : GIT_LOCAL_WRITE.contains s = false) : gitOpOf rest = .unknown := by
  rw [gitOpOf_sub hu hs]
  simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] at hk
  obtain ⟨h1, h2, h3⟩ := hk
  have e1 : (s == lit "push") = false := by simpa using h1
  have e2 : (s == lit "reset") = false := by simpa using h2
  have e3 : (s == lit "remote") = false := by simpa using h3
  simp only [e1, e2, e3, hn, hm, hr, hw, Bool.false_eq_true, if_false, Bool.or_false]

/-! ## Each rule gives its field -/

theorem scan_kill {c ws : Str} (h : killEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.killByPattern = true :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]⟩

theorem scan_network {c ws : Str} (h : networkEvidence ws (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.commandClass = .network :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]⟩

theorem scan_outside {c ws : Str} (h : outsideEvidence ws (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ (r.pathScope = .outside ∨ r.pathScope = .unknown) ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [fires, h]), by
    simp only [scanOf, h]; constructor
    · split <;> simp
    · split <;> simp⟩

theorem scan_traversal {c ws : Str} (h : traversalEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathTraversal = true ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]; split <;> simp⟩

theorem scan_toolchain {c ws : Str} (h : toolchainEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathInToolchain = true ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]; split <;> simp⟩

theorem scan_glob {c ws : Str} (h : globEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathGlob = true ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]; split <;> simp⟩

/-- **Long**: a token the classifier's path check refuses gives the unknown scope. -/
theorem scan_long {c ws : Str} (h : longEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathScope = .unknown :=
  ⟨_, scan_fires (by simp [fires, h]), by simp [scanOf, h]⟩

/-- **git**: the scan's git operation is the most severe of every git token's, and a push names a remote that is
not allowed. -/
theorem scan_git {c ws : Str} (h : gitScan (tokens (strip c)) ≠ .none) :
    ∃ r, scanReading c ws = some r ∧ r.gitOp = gitScan (tokens (strip c)) ∧
      (r.gitOp = .push → r.remoteClass = .other) := by
  have hf : (gitScan (tokens (strip c)) != GitOp.none) = true := by simpa using h
  refine ⟨_, scan_fires (by simp [fires, hf]), by simp [scanOf], ?_⟩
  intro hp; simp only [scanOf] at hp ⊢; simp [hp]

theorem strip_clean (s : Str) : ∀ x ∈ strip s, isStripped x = false := by
  intro x hx
  simp only [strip, List.mem_filter, Bool.not_eq_true'] at hx
  exact hx.2

/-! ## The scan never allows -/

theorem gitOpOf_mem (rest : List Str) : gitOpOf rest ∈ gitOps := by
  unfold gitOpOf
  repeat' split
  all_goals simp [gitOps]

theorem maxOp_mem {a b : GitOp} (ha : a ∈ gitOps) (hb : b ∈ gitOps) : maxOp a b ∈ gitOps := by
  unfold maxOp; split <;> assumption

theorem gitScan_mem : ∀ toks : List Str, gitScan toks ∈ gitOps
  | [] => by simp [gitScan, gitOps]
  | t :: rest => by
    simp only [gitScan]
    apply maxOp_mem
    · split
      · exact gitOpOf_mem rest
      · simp [gitOps]
    · exact gitScan_mem rest

theorem scanOf_mem (k n o tr tc g l : Bool) (gi : GitOp) (hg : gi ∈ gitOps) (h : fires k n o tr tc g l gi = true) :
    scanOf k n o tr tc g l gi ∈ scanSpace := by
  simp only [scanSpace, bools, gitOps, List.mem_flatMap, List.mem_filterMap, List.mem_cons, List.not_mem_nil, or_false]
  refine ⟨k, by cases k <;> simp, n, by cases n <;> simp, o, by cases o <;> simp, tr, by cases tr <;> simp,
    tc, by cases tc <;> simp, g, by cases g <;> simp, l, by cases l <;> simp, gi, by simpa [gitOps] using hg, by simp [h]⟩

theorem scanReading_mem {c ws : Str} {r : Reading} (h : scanReading c ws = some r) : r ∈ scanSpace := by
  rw [scanReading_eq] at h
  simp only at h
  split at h
  · rename_i hf
    simp only [Option.some.injEq] at h
    subst h
    exact scanOf_mem _ _ _ _ _ _ _ _ (gitScan_mem _) hf
  · cases h

/-- **Every reading the scan gives is never allowed, and refused unless it is a push alone**, under a policy the
oracle's `--policy` mode reports as `scan_refused` (all three shipped agent policies are). -/
theorem scan_safe_reading {p : Core.Checked} (hp : scanSafe p = true) {c ws : Str} {r : Reading}
    (h : scanReading c ws = some r) :
    isAllow (Core.decideReading p (.ok r.json)) = false ∧
      (pushOnly r = true ∨ isRefusal (Core.decideReading p (.ok r.json)) = true) := by
  have := List.all_eq_true.mp hp r (scanReading_mem h)
  simp only [Bool.and_eq_true, Bool.not_eq_true', Bool.or_eq_true] at this
  exact this

theorem hookReading_unchanged (d : HookDisk) (disk : Str → Disk) (hook : J) (pd : Option Str) (pc : Str)
    (h : ∀ c, bashCommand? hook = some c → scanReading c (hookCall d hook pd pc).2 = none) :
    hookReading d disk hook pd pc = classify disk [] (hookCall d hook pd pc).1 := by
  unfold hookReading
  simp only
  split
  · split
    · rename_i c hc; rw [h c hc]; rfl
    · rfl
  · rfl

/-- **The scan only ever adds refusals.** Under a policy whose scan readings are safe, the hook reading is the mapped
call's reading unchanged, or one the policy never allows and refuses unless the scan found only a push (which,
with the command class unknown, asks as the unknown reading did). The scan never turns an ask or a refusal into
an allow. -/
theorem hookReading_only_adds_refusals {p : Core.Checked} (hp : scanSafe p = true) (d : HookDisk) (disk : Str → Disk)
    (hook : J) (pd : Option Str) (pc : Str) :
    hookReading d disk hook pd pc = classify disk [] (hookCall d hook pd pc).1 ∨
      (isAllow (Core.decideReading p (.ok (hookReading d disk hook pd pc).json)) = false ∧
       (pushOnly (hookReading d disk hook pd pc) = true ∨
        isRefusal (Core.decideReading p (.ok (hookReading d disk hook pd pc).json)) = true)) := by
  unfold hookReading
  simp only
  split
  · split
    · rename_i c _
      cases hs : scanReading c (hookCall d hook pd pc).2 with
      | none => left; rfl
      | some r => right; exact scan_safe_reading hp hs
    · left; rfl
  · left; rfl

end Classifier
