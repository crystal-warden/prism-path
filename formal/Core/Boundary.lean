-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Theorems
/-!
# The verified core: the system boundary and the policy check

Two checks of a reading (docs/design/spec-verified-core.md, section 6.1, the owner's resolution of
D4): the **system boundary** (`systemBoundary`, every defined field) validates the soundness of the
system and is the boundary `decideReading` applies; the **policy check** (`policyCheck`, the defined
fields the rules read) validates the soundness of a policy. The theorems here say how they relate:

* `systemBoundary_eq`: the system boundary is the core's runtime boundary, the one the verdict uses.
* `policyCheck_of_systemBoundary`: a reading the system boundary accepts passes the policy check.
* `systemBoundary_of_policyCheck`: a reading the policy check refuses is refused by the system boundary,
  so the system boundary is at least as strict on every reading.
* `policyCheck_refuses_routed`: a policy check refusal names a field some rule reads.
* `policyCheck_eq_systemBoundary`: on a policy that routes on every field it defines, the two are equal.
* `route_depends_on_routed`: the route of a reading depends only on the values of the routed fields, so
  a field the policy check does not examine cannot change a route; this is why the policy check is the
  right check of a policy's soundness, and the system boundary the stricter contract of the system.
-/

namespace Core

theorem systemBoundary_eq (p : Checked) (ms : List (String × J)) :
    systemBoundary p ms = firstRefused ms p.defs := rfl

/-- The boundary over a list passes exactly when every definition in it accepts its value. -/
theorem firstRefused_none_iff {ms : List (String × J)} {defs : List FieldDef} :
    firstRefused ms defs = none ↔ ∀ d ∈ defs, ∃ v, acceptField d (field? ms d.name) = .ok v := by
  constructor
  · exact firstRefused_none
  · intro h
    induction defs with
    | nil => rfl
    | cons d ds ih =>
      obtain ⟨v, hv⟩ := h d (List.mem_cons_self ..)
      simp only [firstRefused, hv]
      exact ih (fun x hx => h x (List.mem_cons_of_mem _ hx))

/-- **The system boundary is at least as strict as the policy check**: a reading it accepts passes the
policy check. -/
theorem policyCheck_of_systemBoundary {p : Checked} {ms : List (String × J)}
    (h : systemBoundary p ms = none) : policyCheck p ms = none := by
  have hall := firstRefused_none_iff.mp h
  apply firstRefused_none_iff.mpr
  intro d hd
  exact hall d (List.mem_of_mem_filter hd)

/-- A reading the policy check refuses, the system boundary refuses too. -/
theorem systemBoundary_of_policyCheck {p : Checked} {ms : List (String × J)} {f : String} {e : BoundaryErr}
    (h : policyCheck p ms = some (f, e)) : ∃ g r, systemBoundary p ms = some (g, r) := by
  cases hs : systemBoundary p ms with
  | none => rw [policyCheck_of_systemBoundary hs] at h; cases h
  | some x => exact ⟨x.1, x.2, rfl⟩

/-- A policy check refusal names a defined field that some rule reads. -/
theorem policyCheck_refuses_routed {p : Checked} {ms : List (String × J)} {f : String} {e : BoundaryErr}
    (h : policyCheck p ms = some (f, e)) :
    ∃ d ∈ p.defs, d.name = f ∧ f ∈ rulesFields p.rules ∧ acceptField d (field? ms d.name) = .error e := by
  obtain ⟨pre, d, post, hsplit, hname, herr, _⟩ := firstRefused_spec h
  have hmem : d ∈ p.routedDefs := by rw [hsplit]; simp
  simp only [Checked.routedDefs, List.mem_filter, List.elem_eq_mem, decide_eq_true_eq] at hmem
  exact ⟨d, hmem.1, hname, hname ▸ hmem.2, herr⟩

/-- On a policy whose rules read every field it defines, the policy check is the system boundary. -/
theorem policyCheck_eq_systemBoundary {p : Checked} (hall : ∀ d ∈ p.defs, d.name ∈ rulesFields p.rules)
    (ms : List (String × J)) : policyCheck p ms = systemBoundary p ms := by
  have : p.routedDefs = p.defs := by
    apply List.filter_eq_self.mpr
    intro d hd
    simpa using hall d hd
  simp only [policyCheck, systemBoundary, this]

mutual
/-- A condition's truth depends only on the values of the fields it reads. -/
theorem evalC_congr_on {get get' : String → Option V} :
    ∀ c : LCond, (∀ f ∈ c.fields, get f = get' f) → evalC get c = evalC get' c
  | .always, _ | .never, _ => rfl
  | .truthy f, h => by simp [evalC, h f (by simp [LCond.fields])]
  | .cmp f op k, h => by simp [evalC, h f (by simp [LCond.fields])]
  | .mem f ks, h => by simp [evalC, h f (by simp [LCond.fields])]
  | .nmem f ks, h => by simp [evalC, h f (by simp [LCond.fields])]
  | .not c, h => by simp [evalC, evalC_congr_on c (by simpa [LCond.fields] using h)]
  | .and cs, h => by simp [evalC, evalAll_congr_on cs (by simpa [LCond.fields] using h)]
  | .or cs, h => by simp [evalC, evalAny_congr_on cs (by simpa [LCond.fields] using h)]
theorem evalAll_congr_on {get get' : String → Option V} :
    ∀ cs : List LCond, (∀ f ∈ fieldsOf cs, get f = get' f) → evalAll get cs = evalAll get' cs
  | [], _ => rfl
  | c :: cs, h => by
    have h1 : ∀ f ∈ c.fields, get f = get' f := fun f hf => h f (by simp [fieldsOf, hf])
    have h2 : ∀ f ∈ fieldsOf cs, get f = get' f := fun f hf => h f (by simp [fieldsOf, hf])
    simp [evalAll, evalC_congr_on c h1, evalAll_congr_on cs h2]
theorem evalAny_congr_on {get get' : String → Option V} :
    ∀ cs : List LCond, (∀ f ∈ fieldsOf cs, get f = get' f) → evalAny get cs = evalAny get' cs
  | [], _ => rfl
  | c :: cs, h => by
    have h1 : ∀ f ∈ c.fields, get f = get' f := fun f hf => h f (by simp [fieldsOf, hf])
    have h2 : ∀ f ∈ fieldsOf cs, get f = get' f := fun f hf => h f (by simp [fieldsOf, hf])
    simp [evalAny, evalC_congr_on c h1, evalAny_congr_on cs h2]
end

/-- First match depends only on the fields the rules read. -/
theorem firstMatch_congr_on {get get' : String → Option V} :
    ∀ rules : List (Rule LCond), (∀ f ∈ rulesFields rules, get f = get' f) →
      firstMatch get rules = firstMatch get' rules
  | [], _ => rfl
  | r :: rs, h => by
    have h1 : ∀ f ∈ r.cond.fields, get f = get' f := fun f hf => h f (by simp [rulesFields, hf])
    have h2 : ∀ f ∈ rulesFields rs, get f = get' f := fun f hf => h f (by simp [rulesFields, hf])
    simp only [firstMatch, evalC_congr_on r.cond h1, firstMatch_congr_on rs h2]

/-- **The route depends only on the routed fields.** Two readings that both pass the system boundary
and hold the same values on every field the rules read get the same verdict: a field the policy check
does not examine cannot change a route. -/
theorem route_depends_on_routed (p : Checked) {ms ms' : List (String × J)}
    (h : systemBoundary p ms = none) (h' : systemBoundary p ms' = none)
    (hr : ∀ f ∈ rulesFields p.rules, field? ms f = field? ms' f) :
    decideReading p (.ok (.obj ms)) = decideReading p (.ok (.obj ms')) := by
  have hb : firstRefused ms p.defs = none := h
  have hb' : firstRefused ms' p.defs = none := h'
  have hget : ∀ f ∈ rulesFields p.rules, canonicalGet p.defs ms f = canonicalGet p.defs ms' f := by
    intro f hf
    simp only [canonicalGet, hr f hf]
  simp only [decideReading, hb, hb', firstMatch_congr_on p.rules hget]

end Core
