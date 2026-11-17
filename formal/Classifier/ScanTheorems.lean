-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Scan
/-!
# The hazard scan's theorems

* Each detection rule, as stated: `scan_kill`, `scan_network`, `scan_outside`, `scan_traversal`, `scan_toolchain`,
  with the evidence lemmas `killEvidence_of_word`, `networkEvidence_of_word`, `networkEvidence_of_url`,
  `outsideEvidence_of_token`, `traversalEvidence_of_token`, `toolchainEvidence_of_token`.
* No evidence, no change: `scan_none`, `hookReading_unchanged`.
* The scan only ever adds refusals: `scanReading_mem`, `scan_refuses`, `hookReading_only_adds_refusals`.
-/

namespace Classifier

open Core (J)

theorem scanReading_eq (c ws : Str) : scanReading c ws =
    let t := strip c
    if killEvidence t || networkEvidence t || outsideEvidence ws t || traversalEvidence t || toolchainEvidence t then
      some (scanOf (killEvidence t) (networkEvidence t) (outsideEvidence ws t) (traversalEvidence t) (toolchainEvidence t))
    else none := rfl

/-- A scan that finds evidence gives `scanOf` of what it found. -/
theorem scan_fires {c ws : Str} (h : (killEvidence (strip c) || networkEvidence (strip c) || outsideEvidence ws (strip c) ||
      traversalEvidence (strip c) || toolchainEvidence (strip c)) = true) :
    scanReading c ws = some (scanOf (killEvidence (strip c)) (networkEvidence (strip c)) (outsideEvidence ws (strip c))
      (traversalEvidence (strip c)) (toolchainEvidence (strip c))) := by
  rw [scanReading_eq]; simp only [h, if_true]

/-- **No evidence, no change**: the scan gives nothing. -/
theorem scan_none {c ws : Str} (h : (killEvidence (strip c) || networkEvidence (strip c) || outsideEvidence ws (strip c) ||
      traversalEvidence (strip c) || toolchainEvidence (strip c)) = false) : scanReading c ws = none := by
  rw [scanReading_eq]; simp only [h, Bool.false_eq_true, if_false]

/-! ## The detection rules -/

theorem killEvidence_of_word {t w : Str} (hw : w ∈ asciiWords t) (hk : w = lit "pkill" ∨ w = lit "killall" ∨ w = lit "kill") :
    killEvidence t = true :=
  List.any_eq_true.mpr ⟨w, hw, by rcases hk with rfl | rfl | rfl <;> decide⟩

theorem networkEvidence_of_word {t w : Str} (hw : w ∈ asciiWords t) (hn : NETWORK.contains w = true) :
    networkEvidence t = true := by
  simp only [networkEvidence, Bool.or_eq_true]
  exact Or.inl (List.any_eq_true.mpr ⟨w, hw, hn⟩)

theorem networkEvidence_of_url {t : Str} (hu : hasURL t = true) : networkEvidence t = true := by
  simp [networkEvidence, hu]

theorem outsideEvidence_of_token {ws t tok : Str} (ht : tok ∈ tokens t) (ho : outsideToken ws tok = true) :
    outsideEvidence ws t = true := List.any_eq_true.mpr ⟨tok, ht, ho⟩

/-- A token that starts with `/` and is neither the workspace nor below it, or starts with `~`, is outside. -/
theorem outsideToken_abs {ws tok : Str} (hs : startsWith tok (lit "/") = true) (hne : tok ≠ ws)
    (hb : startsWith tok (ws ++ ['/']) = false) : outsideToken ws tok = true := by
  have : (tok == ws) = false := by simpa using hne
  simp [outsideToken, hs, this, hb]

theorem outsideToken_home {ws tok : Str} (hs : startsWith tok (lit "~") = true) : outsideToken ws tok = true := by
  simp [outsideToken, hs]

theorem traversalEvidence_of_token {t tok : Str} (ht : tok ∈ tokens t) (hd : lit ".." ∈ splitSlash tok) :
    traversalEvidence t = true := List.any_eq_true.mpr ⟨tok, ht, by simpa using hd⟩

theorem toolchainEvidence_of_token {t tok : Str} (ht : tok ∈ tokens t) (hd : lit ".toolchain" ∈ splitSlash tok) :
    toolchainEvidence t = true := List.any_eq_true.mpr ⟨tok, ht, by simpa using hd⟩

/-- **Kill**: a `pkill`, `killall` or `kill` word in the stripped text gives `kill_by_pattern`. -/
theorem scan_kill {c ws : Str} (h : killEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.killByPattern = true :=
  ⟨_, scan_fires (by simp [h]), by simp [scanOf, h]⟩

/-- **Network**: a network word or a URL scheme gives `command_class` network. -/
theorem scan_network {c ws : Str} (h : networkEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.commandClass = .network :=
  ⟨_, scan_fires (by simp [h]), by simp [scanOf, h]⟩

/-- **Outside**: an outside token gives `path_scope` outside. -/
theorem scan_outside {c ws : Str} (h : outsideEvidence ws (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathScope = .outside ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [h]), by simp [scanOf, h]; split <;> simp⟩

/-- **Traversal**: a `..` component gives `path_traversal`, on a reading that is mutating or network. -/
theorem scan_traversal {c ws : Str} (h : traversalEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathTraversal = true ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [h]), by simp [scanOf, h]; split <;> simp⟩

/-- **Toolchain**: a `.toolchain` component gives `path_in_toolchain`, on a reading that is mutating or network. -/
theorem scan_toolchain {c ws : Str} (h : toolchainEvidence (strip c) = true) :
    ∃ r, scanReading c ws = some r ∧ r.pathInToolchain = true ∧ r.commandClass ≠ .unknown :=
  ⟨_, scan_fires (by simp [h]), by simp [scanOf, h]; split <;> simp⟩

/-- Stripping removes every backslash and quote, so `pk\ill` and `p'k'ill` are scanned as `pkill`. -/
theorem strip_clean (s : Str) : ∀ x ∈ strip s, isStripped x = false := by
  intro x hx
  simp only [strip, List.mem_filter, Bool.not_eq_true'] at hx
  exact hx.2

/-! ## The scan only ever adds refusals -/

theorem scanOf_mem (k n o tr tc : Bool) (h : (k || n || o || tr || tc) = true) : scanOf k n o tr tc ∈ scanSpace := by
  cases k <;> cases n <;> cases o <;> cases tr <;> cases tc <;> simp_all [scanSpace, bools] <;> decide

theorem scanReading_mem {c ws : Str} {r : Reading} (h : scanReading c ws = some r) : r ∈ scanSpace := by
  rw [scanReading_eq] at h
  simp only at h
  split at h
  · rename_i hf
    simp only [Option.some.injEq] at h
    subst h
    exact scanOf_mem _ _ _ _ _ hf
  · cases h

/-- **Every reading the scan gives is refused** by a policy the oracle's `--policy` mode reports as `scan_refused`
(all three shipped agent policies are). -/
theorem scan_refuses {p : Core.Checked} (hp : scanSafe p = true) {c ws : Str} {r : Reading}
    (h : scanReading c ws = some r) : isRefusal (Core.decideReading p (.ok r.json)) = true :=
  List.all_eq_true.mp hp r (scanReading_mem h)

/-- **No evidence, no change**: when the scan finds nothing the hook reading is the mapped call's reading. -/
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

/-- **The scan only ever adds refusals.** Under a policy whose scan readings are all refused, the hook reading is
either the mapped call's reading unchanged, or a reading the policy refuses: the scan never turns an ask or a
refusal into an allow. -/
theorem hookReading_only_adds_refusals {p : Core.Checked} (hp : scanSafe p = true) (d : HookDisk) (disk : Str → Disk)
    (hook : J) (pd : Option Str) (pc : Str) :
    hookReading d disk hook pd pc = classify disk [] (hookCall d hook pd pc).1 ∨
      isRefusal (Core.decideReading p (.ok (hookReading d disk hook pd pc).json)) = true := by
  unfold hookReading
  simp only
  split
  · split
    · rename_i c _
      cases hs : scanReading c (hookCall d hook pd pc).2 with
      | none => left; rfl
      | some r => right; exact scan_refuses hp hs
    · left; rfl
  · left; rfl

end Classifier
