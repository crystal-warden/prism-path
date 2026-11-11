-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Eval
import Mathlib.Tactic
/-!
# The verified core: termination, no fail-open, refusal completeness, determinism

The statements of docs/design/spec-verified-core.md section 6, proven about the executable
definitions the oracle runs (`Core.verdict`), not about a separate model.
-/

namespace Core

/-! ## Termination and a bound on evaluation -/

/-- **Termination.** The core's meaning is a total function: every image and every reading, read or
not, has exactly one verdict. Lean accepts `verdict` and everything it calls only as structural
recursion (no `partial`, no well founded recursion), so this statement is the type checker's own
guarantee, written down. -/
theorem verdict_total (image reading : Except DocErr J) : ∃ v, verdict image reading = v := ⟨_, rfl⟩

theorem verdictBytes_total (image reading : ByteArray) : ∃ v, verdictBytes image reading = v := ⟨_, rfl⟩

mutual
/-- The atoms of a lowered condition: the comparisons evaluation performs. -/
def LCond.atoms : LCond → Nat
  | .always | .never => 0
  | .truthy _ | .cmp _ _ _ | .mem _ _ | .nmem _ _ => 1
  | .not c => c.atoms
  | .and cs | .or cs => atomsOf cs
def atomsOf : List LCond → Nat
  | [] => 0
  | c :: cs => c.atoms + atomsOf cs
end

/-- The atom evaluations routing performs: every atom of every rule tried, up to the first match. -/
def matchSteps (get : String → Option V) : List (Rule LCond) → Nat
  | [] => 0
  | r :: rs => r.cond.atoms + (if evalC get r.cond then 0 else matchSteps get rs)

/-- The size of a policy: its atoms. -/
def policyAtoms (rules : List (Rule LCond)) : Nat := (rules.map (fun r => r.cond.atoms)).sum

/-- **Bounded cost.** Routing one reading evaluates at most as many atoms as the policy has, whatever
the reading; with the boundary's one check per definition, a verdict costs at most
`defs + atoms` comparisons, a bound fixed when the policy is signed. -/
theorem matchSteps_le (get : String → Option V) (rules : List (Rule LCond)) :
    matchSteps get rules ≤ policyAtoms rules := by
  induction rules with
  | nil => simp [matchSteps, policyAtoms]
  | cons r rs ih =>
    simp only [matchSteps, policyAtoms, List.map_cons, List.sum_cons] at ih ⊢
    split <;> omega

/-- `firstMatch` and the step count agree on where routing stops. -/
theorem firstMatch_none_steps {get : String → Option V} {rules : List (Rule LCond)}
    (h : firstMatch get rules = none) : matchSteps get rules = policyAtoms rules := by
  induction rules with
  | nil => rfl
  | cons r rs ih =>
    simp only [firstMatch] at h
    split at h
    · simp at h
    · rename_i hf
      simp only [matchSteps, policyAtoms, List.map_cons, List.sum_cons, hf] at ih ⊢
      simp [ih h, policyAtoms]

/-! ## What `firstMatch` and `firstRefused` mean -/

/-- A route names the first rule whose condition holds: every earlier rule's condition fails. -/
theorem firstMatch_spec {get : String → Option V} {rules : List (Rule LCond)} {t : String}
    (h : firstMatch get rules = some t) :
    ∃ pre r post, rules = pre ++ r :: post ∧ r.target = t ∧ evalC get r.cond = true ∧
      ∀ q ∈ pre, evalC get q.cond = false := by
  induction rules with
  | nil => simp [firstMatch] at h
  | cons r rs ih =>
    simp only [firstMatch] at h
    split at h
    · rename_i hr
      exact ⟨[], r, rs, rfl, (Option.some.inj h), hr, by simp⟩
    · rename_i hr
      obtain ⟨pre, q, post, hrs, hq, hev, hpre⟩ := ih h
      refine ⟨r :: pre, q, post, by simp [hrs], hq, hev, ?_⟩
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · simpa using hr
      · exact hpre x hx

/-- No route means no rule's condition holds. -/
theorem firstMatch_none {get : String → Option V} {rules : List (Rule LCond)}
    (h : firstMatch get rules = none) : ∀ r ∈ rules, evalC get r.cond = false := by
  induction rules with
  | nil => simp
  | cons r rs ih =>
    simp only [firstMatch] at h
    split at h
    · simp at h
    · rename_i hr
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · simpa using hr
      · exact ih h x hx

/-- A boundary refusal names the first definition, in order, that refuses its value, with its reason. -/
theorem firstRefused_spec {ms : List (String × J)} {defs : List FieldDef} {f : String} {e : BoundaryErr}
    (h : firstRefused ms defs = some (f, e)) :
    ∃ pre d post, defs = pre ++ d :: post ∧ d.name = f ∧ acceptField d (field? ms d.name) = .error e ∧
      ∀ q ∈ pre, ∃ v, acceptField q (field? ms q.name) = .ok v := by
  induction defs with
  | nil => simp [firstRefused] at h
  | cons d ds ih =>
    simp only [firstRefused] at h
    split at h
    · rename_i e' he'
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      exact ⟨[], d, ds, rfl, rfl, he', by simp⟩
    · rename_i v hv
      obtain ⟨pre, q, post, hds, hq, hev, hpre⟩ := ih h
      refine ⟨d :: pre, q, post, by simp [hds], hq, hev, ?_⟩
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact ⟨v, hv⟩
      · exact hpre x hx

/-- The boundary passes only when every definition accepts its value. -/
theorem firstRefused_none {ms : List (String × J)} {defs : List FieldDef}
    (h : firstRefused ms defs = none) : ∀ d ∈ defs, ∃ v, acceptField d (field? ms d.name) = .ok v := by
  induction defs with
  | nil => simp
  | cons d ds ih =>
    simp only [firstRefused] at h
    split at h
    · simp at h
    · rename_i v hv
      intro x hx
      rcases List.mem_cons.mp hx with rfl | hx
      · exact ⟨v, hv⟩
      · exact ih h x hx

/-! ## No fail open -/

theorem decideReading_not_policy (p : Checked) (r : Except DocErr J) (e : PolicyErr) :
    decideReading p r ≠ .refuse (.policy e) := by
  unfold decideReading
  repeat' split
  all_goals simp

/-- **No fail open, policy.** A policy image that does not read, does not decode, or breaks a
definition or a policy rule refuses every reading with that refusal, and routes none. -/
theorem policy_refusal_refuses_all {image : Except DocErr J} {e : PolicyErr}
    (h : loadPolicy image = .error e) (reading : Except DocErr J) :
    verdict image reading = .refuse (.policy e) := by
  simp [verdict, h]

/-- An unreadable image is a policy refusal naming the document rule it broke. -/
theorem unreadable_image_refused (e : DocErr) (reading : Except DocErr J) :
    verdict (.error e) reading = .refuse (.policy (.unreadable e)) :=
  policy_refusal_refuses_all rfl reading

/-- **No fail open, reading.** Under an accepted policy, a reading that does not read, is not an
object, or holds a value its definition refuses is refused, and routes nowhere. -/
theorem unreadable_reading_refused {image : Except DocErr J} {p : Checked} (hp : loadPolicy image = .ok p)
    (e : DocErr) : verdict image (.error e) = .refuse (.readingUnreadable e) := by
  simp [verdict, hp, decideReading]

theorem boundary_refusal {image : Except DocErr J} {p : Checked} (hp : loadPolicy image = .ok p)
    {ms : List (String × J)} {f : String} {e : BoundaryErr} (hb : firstRefused ms p.defs = some (f, e)) :
    verdict image (.ok (.obj ms)) = .refuse (.contract f e) := by
  simp [verdict, hp, decideReading, hb]

/-- **No fail open, the allow.** A route is produced only when the image read and passed every check,
the reading read as an object and passed the boundary on every definition, and the route is the
target of the first rule whose condition holds on the canonical reading, every earlier rule failing. -/
theorem route_sound {image reading : Except DocErr J} {t : String} (h : verdict image reading = .route t) :
    ∃ p ms, loadPolicy image = .ok p ∧ reading = .ok (.obj ms) ∧
      (∀ d ∈ p.defs, ∃ v, acceptField d (field? ms d.name) = .ok v) ∧
      ∃ pre r post, p.rules = pre ++ r :: post ∧ r.target = t ∧
        evalC (canonicalGet p.defs ms) r.cond = true ∧
        ∀ q ∈ pre, evalC (canonicalGet p.defs ms) q.cond = false := by
  unfold verdict at h
  split at h
  · simp at h
  · rename_i p hp
    unfold decideReading at h
    split at h
    · simp at h
    · rename_i ms
      split at h
      · simp at h
      · rename_i hb
        split at h
        · rename_i t' hm
          simp only [Verdict.route.injEq] at h
          subst h
          exact ⟨p, ms, hp, rfl, firstRefused_none hb, firstMatch_spec hm⟩
        · simp at h
    · simp at h

/-! ## Refusal completeness -/

/-- **Refusal completeness.** Every image and reading has exactly one verdict, and each verdict is
characterized by the stage that produced it: a route, or one refusal from the closed `Refusal` type,
each with a registered or proposed cause (spec section 5). No input escapes as an exception, a crash
or an undefined result: `verdict` is total and returns only these. -/
theorem verdict_cases (image reading : Except DocErr J) :
    (∃ e, loadPolicy image = .error e ∧ verdict image reading = .refuse (.policy e)) ∨
    (∃ p e, loadPolicy image = .ok p ∧ reading = .error e ∧
      verdict image reading = .refuse (.readingUnreadable e)) ∨
    (∃ p j, loadPolicy image = .ok p ∧ reading = .ok j ∧ (∀ ms, j ≠ .obj ms) ∧
      verdict image reading = .refuse .readingNotObject) ∨
    (∃ p ms f e, loadPolicy image = .ok p ∧ reading = .ok (.obj ms) ∧
      firstRefused ms p.defs = some (f, e) ∧ verdict image reading = .refuse (.contract f e)) ∨
    (∃ p ms, loadPolicy image = .ok p ∧ reading = .ok (.obj ms) ∧ firstRefused ms p.defs = none ∧
      firstMatch (canonicalGet p.defs ms) p.rules = none ∧ verdict image reading = .refuse .noMatch) ∨
    (∃ p ms t, loadPolicy image = .ok p ∧ reading = .ok (.obj ms) ∧ firstRefused ms p.defs = none ∧
      firstMatch (canonicalGet p.defs ms) p.rules = some t ∧ verdict image reading = .route t) := by
  cases hp : loadPolicy image with
  | error e => exact Or.inl ⟨e, rfl, by simp [verdict, hp]⟩
  | ok p =>
    cases reading with
    | error e => exact Or.inr (Or.inl ⟨p, e, rfl, rfl, by simp [verdict, hp, decideReading]⟩)
    | ok j =>
      cases j with
      | obj ms =>
        cases hb : firstRefused ms p.defs with
        | some fe =>
          obtain ⟨f, e⟩ := fe
          exact Or.inr (Or.inr (Or.inr (Or.inl ⟨p, ms, f, e, rfl, rfl, hb, by simp [verdict, hp, decideReading, hb]⟩)))
        | none =>
          cases hm : firstMatch (canonicalGet p.defs ms) p.rules with
          | none => exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inl
              ⟨p, ms, rfl, rfl, hb, hm, by simp [verdict, hp, decideReading, hb, hm]⟩))))
          | some t => exact Or.inr (Or.inr (Or.inr (Or.inr (Or.inr
              ⟨p, ms, t, rfl, rfl, hb, hm, by simp [verdict, hp, decideReading, hb, hm]⟩))))
      | null => exact Or.inr (Or.inr (Or.inl ⟨p, _, rfl, rfl, by simp, by simp [verdict, hp, decideReading]⟩))
      | bool _ => exact Or.inr (Or.inr (Or.inl ⟨p, _, rfl, rfl, by simp, by simp [verdict, hp, decideReading]⟩))
      | int _ => exact Or.inr (Or.inr (Or.inl ⟨p, _, rfl, rfl, by simp, by simp [verdict, hp, decideReading]⟩))
      | str _ => exact Or.inr (Or.inr (Or.inl ⟨p, _, rfl, rfl, by simp, by simp [verdict, hp, decideReading]⟩))
      | arr _ => exact Or.inr (Or.inr (Or.inl ⟨p, _, rfl, rfl, by simp, by simp [verdict, hp, decideReading]⟩))

/-- A policy refusal in a verdict is exactly a policy that failed: the reading stage never produces one. -/
theorem policy_refusal_iff (image reading : Except DocErr J) (e : PolicyErr) :
    verdict image reading = .refuse (.policy e) ↔ loadPolicy image = .error e := by
  constructor
  · intro h
    unfold verdict at h
    split at h
    · rename_i e' he'
      simp only [Verdict.refuse.injEq, Refusal.policy.injEq] at h
      subst h; exact he'
    · exact absurd h (decideReading_not_policy _ _ _)
  · intro h; exact policy_refusal_refuses_all h reading

/-- A route never names anything but a rule's target. -/
theorem route_is_a_target {image reading : Except DocErr J} {t : String} (h : verdict image reading = .route t) :
    ∃ p, loadPolicy image = .ok p ∧ ∃ r ∈ p.rules, r.target = t := by
  obtain ⟨p, _ms, hp, _hr, _hb, pre, r, post, hrules, ht, _hev, _⟩ := route_sound h
  exact ⟨p, hp, r, by simp [hrules], ht⟩

/-- The verdicts are a closed set: a route or a refusal. -/
theorem verdict_route_or_refuse (v : Verdict) : (∃ t, v = .route t) ∨ (∃ r, v = .refuse r) := by
  cases v with
  | route t => exact Or.inl ⟨t, rfl⟩
  | refuse r => exact Or.inr ⟨r, rfl⟩

/-! ## Determinism -/

theorem hasKey_iff (k : String) (ms : List (String × J)) : hasKey k ms = true ↔ k ∈ ms.map (·.1) := by
  induction ms with
  | nil => simp [hasKey]
  | cons m ms ih =>
    obtain ⟨k', v⟩ := m
    simp only [hasKey, Bool.or_eq_true, beq_iff_eq, ih, List.map_cons, List.mem_cons]

theorem keysDistinct_iff (ms : List (String × J)) : keysDistinct ms = true ↔ (ms.map (·.1)).Nodup := by
  induction ms with
  | nil => simp [keysDistinct]
  | cons m ms ih =>
    obtain ⟨k, v⟩ := m
    simp only [keysDistinct, Bool.and_eq_true, Bool.not_eq_true', List.map_cons, List.nodup_cons, ih]
    constructor
    · rintro ⟨h1, h2⟩
      refine ⟨?_, h2⟩
      intro hk
      have := (hasKey_iff k ms).mpr hk
      simp [this] at h1
    · rintro ⟨h1, h2⟩
      refine ⟨?_, h2⟩
      cases h : hasKey k ms
      · rfl
      · exact absurd ((hasKey_iff k ms).mp h) h1

theorem field?_none_iff (ms : List (String × J)) (k : String) : field? ms k = none ↔ ∀ v, (k, v) ∉ ms := by
  unfold field?
  constructor
  · intro h v hv
    split at h
    · simp at h
    · rename_i hf
      have := List.find?_eq_none.mp hf (k, v) hv
      simp at this
  · intro h
    split
    · rename_i k' v' hf
      have hmem := List.mem_of_find?_eq_some hf
      have hk := List.find?_some hf
      simp at hk
      subst hk
      exact absurd hmem (h v')
    · rfl

theorem field?_some_iff {ms : List (String × J)} (hnd : (ms.map (·.1)).Nodup) (k : String) (v : J) :
    field? ms k = some v ↔ (k, v) ∈ ms := by
  unfold field?
  constructor
  · intro h
    split at h
    · rename_i k' v' hf
      simp only [Option.some.injEq] at h
      subst h
      have hmem := List.mem_of_find?_eq_some hf
      have hk := List.find?_some hf
      simp at hk
      subst hk
      exact hmem
    · simp at h
  · intro hmem
    split
    · rename_i k' v' hf
      have hmem' := List.mem_of_find?_eq_some hf
      have hk := List.find?_some hf
      simp at hk
      subst hk
      congr
      exact (List.inj_on_of_nodup_map hnd hmem' hmem rfl |> fun h => (Prod.mk.inj h).2)
    · rename_i hf
      have := List.find?_eq_none.mp hf (k, v) hmem
      simp at this

/-- Reading a key does not depend on the order of an object's members, when no key repeats. -/
theorem field?_perm {ms ms' : List (String × J)} (hp : ms.Perm ms') (hnd : (ms.map (·.1)).Nodup) (k : String) :
    field? ms k = field? ms' k := by
  have hnd' : (ms'.map (·.1)).Nodup := (hp.map _).nodup_iff.mp hnd
  cases h : field? ms k with
  | none =>
    symm
    rw [field?_none_iff] at h ⊢
    intro v hv
    exact h v (hp.mem_iff.mpr hv)
  | some v =>
    symm
    rw [field?_some_iff hnd] at h
    rw [field?_some_iff hnd']
    exact hp.mem_iff.mp h

theorem firstRefused_congr {ms ms' : List (String × J)} (h : ∀ k, field? ms k = field? ms' k) :
    ∀ defs, firstRefused ms defs = firstRefused ms' defs := by
  intro defs
  induction defs with
  | nil => rfl
  | cons d ds ih => simp only [firstRefused, h d.name, ih]

theorem canonicalGet_congr {ms ms' : List (String × J)} (h : ∀ k, field? ms k = field? ms' k)
    (defs : List FieldDef) : canonicalGet defs ms = canonicalGet defs ms' := by
  funext f
  simp only [canonicalGet, h f]

/-- **Determinism.** The verdict on a reading depends on its content, not its spelling: two readings
whose members are the same up to order (no key repeating, as the canon/2 reader guarantees) have the
same verdict. -/
theorem decideReading_perm (p : Checked) {ms ms' : List (String × J)} (hp : ms.Perm ms')
    (hnd : keysDistinct ms = true) :
    decideReading p (.ok (.obj ms)) = decideReading p (.ok (.obj ms')) := by
  have hk := field?_perm hp ((keysDistinct_iff ms).mp hnd)
  simp only [decideReading, firstRefused_congr hk, canonicalGet_congr hk]

theorem verdict_perm (image : Except DocErr J) {ms ms' : List (String × J)} (hp : ms.Perm ms')
    (hnd : keysDistinct ms = true) :
    verdict image (.ok (.obj ms)) = verdict image (.ok (.obj ms')) := by
  unfold verdict
  split
  · rfl
  · exact decideReading_perm _ hp hnd

/-- The reader never returns an object with a repeated key, anywhere in the document. -/
theorem readChars_wf {cs : List Char} {j : J} (h : readChars cs = .ok j) : wfJ j = true := by
  unfold readChars at h
  split at h
  · simp at h
  · split at h
    · split at h
      · rename_i hw; simp only [Except.ok.injEq] at h; subst h; exact hw
      · simp at h
    · simp at h

theorem readChars_obj_distinct {cs : List Char} {ms : List (String × J)} (h : readChars cs = .ok (.obj ms)) :
    keysDistinct ms = true := by
  have := readChars_wf h
  simp only [wfJ, Bool.and_eq_true] at this
  exact this.1

/-- Determinism on text: the verdicts of two reading documents that read as the same members in
another order are equal. -/
theorem verdict_text_perm (image : Except DocErr J) {cs cs' : List Char} {ms ms' : List (String × J)}
    (h : readChars cs = .ok (.obj ms)) (h' : readChars cs' = .ok (.obj ms')) (hp : ms.Perm ms') :
    verdict image (readChars cs) = verdict image (readChars cs') := by
  rw [h, h']
  exact verdict_perm image hp (readChars_obj_distinct h)

mutual
/-- The evaluator is a function of the canonical values alone: two value maps that agree on every
field give every condition the same truth. -/
theorem evalC_congr {get get' : String → Option V} (h : ∀ f, get f = get' f) :
    ∀ c : LCond, evalC get c = evalC get' c
  | .always | .never => rfl
  | .truthy f => by simp [evalC, h f]
  | .cmp f op k => by simp [evalC, h f]
  | .mem f ks => by simp [evalC, h f]
  | .nmem f ks => by simp [evalC, h f]
  | .not c => by simp [evalC, evalC_congr h c]
  | .and cs => by simp [evalC, evalAll_congr h cs]
  | .or cs => by simp [evalC, evalAny_congr h cs]
theorem evalAll_congr {get get' : String → Option V} (h : ∀ f, get f = get' f) :
    ∀ cs : List LCond, evalAll get cs = evalAll get' cs
  | [] => rfl
  | c :: cs => by simp [evalAll, evalC_congr h c, evalAll_congr h cs]
theorem evalAny_congr {get get' : String → Option V} (h : ∀ f, get f = get' f) :
    ∀ cs : List LCond, evalAny get cs = evalAny get' cs
  | [] => rfl
  | c :: cs => by simp [evalAny, evalC_congr h c, evalAny_congr h cs]
end

end Core
