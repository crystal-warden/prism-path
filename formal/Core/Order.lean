-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Theorems
/-!
# The verified core: a refused policy names its first problem in the stated order (D7)

A policy can have several problems. The core refuses it for exactly one, and this file proves which:
the first problem in the order of docs/design/spec-verified-core.md, section 4. The order is written
down here as a list, `policyProblems`, that enumerates the problems phase by phase, as the reference's
`field_definitions.core_problems` and the Rust port's `core_problems` enumerate them for diagnostics:

1. the document (`policy:unreadable`), then the image's own shape and its definitions as text;
2. decoding, rule by rule, each rule's first decoding refusal (depth first and left to right within it,
   its depth after its whole condition);
3. the definitions, in code point order of their names;
4. lowering, rule by rule and **atom by atom** (`Cond.atoms`, depth first and left to right), each atom's
   refusal against its field's definition;
5. rule 6, the fields that allow absence, in code point order.

`loadPolicy_first_problem` proves that the refusal `loadPolicy` computes, which stops at its first
failure, is the head of that list, and that a policy is accepted exactly when the list is empty.
`lowerCond_first_atom` proves the atom by atom order inside one condition. So "the cause of a refused
policy" is one function of the image, and every implementation that names the head of the same list
names the same cause.
-/

namespace Core

/-- The refusal of a check, if it refused. -/
def errOf {α : Type} : PE α → Option PolicyErr
  | .error e => some e
  | .ok _ => none

/-- The result of a check, if it passed. -/
def okOf {α : Type} : PE α → Option α
  | .error _ => none
  | .ok a => some a

@[simp] theorem errOf_error {α : Type} (e : PolicyErr) : errOf (.error e : PE α) = some e := rfl
@[simp] theorem errOf_ok {α : Type} (a : α) : errOf (.ok a : PE α) = none := rfl

theorem errOf_eq_none {α : Type} (x : PE α) : errOf x = none ↔ ∃ a, x = .ok a := by
  cases x <;> simp [errOf]

/-! ## The atoms of a condition, depth first and left to right -/

mutual
/-- The atoms of a decoded condition, in the order lowering meets them. -/
def Cond.atoms : Cond → List Cond
  | .always => []
  | .never => []
  | .truthy f => [.truthy f]
  | .cmp f op k => [.cmp f op k]
  | .mem f ks => [.mem f ks]
  | .nmem f ks => [.nmem f ks]
  | .not c => c.atoms
  | .and cs => condsAtoms cs
  | .or cs => condsAtoms cs
def condsAtoms : List Cond → List Cond
  | [] => []
  | c :: cs => c.atoms ++ condsAtoms cs
end

/-- The lowering refusal of each atom, in order. -/
def atomProblems (defs : List FieldDef) (atoms : List Cond) : List PolicyErr :=
  atoms.filterMap (fun a => errOf (lowerCond defs a))

theorem atomProblems_append (defs : List FieldDef) (xs ys : List Cond) :
    atomProblems defs (xs ++ ys) = atomProblems defs xs ++ atomProblems defs ys := by
  simp [atomProblems, List.filterMap_append]

mutual
/-- **Atom by atom.** Lowering one condition refuses for the first atom that its field's definition
refuses, depth first and left to right, and passes exactly when every atom passes. -/
theorem lowerCond_first_atom (defs : List FieldDef) :
    ∀ c : Cond, errOf (lowerCond defs c) = (atomProblems defs c.atoms).head?
  | .always => by simp [lowerCond, Cond.atoms, atomProblems]
  | .never => by simp [lowerCond, Cond.atoms, atomProblems]
  | .truthy f => by
    simp only [Cond.atoms, atomProblems, List.filterMap_cons, List.filterMap_nil]
    cases h : errOf (lowerCond defs (.truthy f)) <;> simp
  | .cmp f op k => by
    simp only [Cond.atoms, atomProblems, List.filterMap_cons, List.filterMap_nil]
    cases h : errOf (lowerCond defs (.cmp f op k)) <;> simp
  | .mem f ks => by
    simp only [Cond.atoms, atomProblems, List.filterMap_cons, List.filterMap_nil]
    cases h : errOf (lowerCond defs (.mem f ks)) <;> simp
  | .nmem f ks => by
    simp only [Cond.atoms, atomProblems, List.filterMap_cons, List.filterMap_nil]
    cases h : errOf (lowerCond defs (.nmem f ks)) <;> simp
  | .not c => by
    rw [Cond.atoms, ← lowerCond_first_atom defs c, lowerCond]
    cases lowerCond defs c <;> rfl
  | .and cs => by
    rw [Cond.atoms, ← lowerConds_first_atom defs cs, lowerCond]
    cases lowerConds defs cs <;> rfl
  | .or cs => by
    rw [Cond.atoms, ← lowerConds_first_atom defs cs, lowerCond]
    cases lowerConds defs cs <;> rfl
theorem lowerConds_first_atom (defs : List FieldDef) :
    ∀ cs : List Cond, errOf (lowerConds defs cs) = (atomProblems defs (condsAtoms cs)).head?
  | [] => by simp [lowerConds, condsAtoms, atomProblems]
  | c :: cs => by
    rw [condsAtoms, atomProblems_append, List.head?_append, ← lowerCond_first_atom defs c,
      ← lowerConds_first_atom defs cs, lowerConds]
    cases lowerCond defs c <;> cases lowerConds defs cs <;> rfl
end

/-! ## The phases -/

/-- The image's own shape, its format tag and its definitions as text, before any rule is decoded. -/
def imageHead : J → PE (List (String × String) × List J)
  | .obj ms =>
    if !onlyKeys ms ["format", "fields", "rules"] then .error (.shape "image-key")
    else match field? ms "format", field? ms "fields", field? ms "rules" with
      | some (.str f), some (.obj fs), some (.arr rs) =>
        if f != formatTag then .error (.shape "format")
        else match decodeFields fs with
          | .error e => .error e
          | .ok fields => .ok (fields, rs)
      | _, _, _ => .error (.shape "image")
  | _ => .error (.shape "image")

/-- Decoding an image is its head, then its rules. -/
theorem decodeImage_head (j : J) :
    decodeImage j = match imageHead j with
      | .error e => .error e
      | .ok (fields, rs) => match decodeRules rs with
        | .error e => .error e
        | .ok rules => .ok { fields := fields, rules := rules } := by
  cases j with
  | obj ms =>
    simp only [decodeImage, imageHead]
    split
    · rfl
    · split
      · rename_i f fs rs h1 h2 h3
        simp only [h1, h2, h3]
        split
        · rfl
        · cases decodeFields fs <;> dsimp only <;> cases decodeRules rs <;> rfl
      · rename_i hno
        split
        · rename_i e heq
          split at heq
          · rename_i f fs rs h1 h2 h3
            exact (hno f fs rs h1 h2 h3).elim
          · cases heq; rfl
        · rename_i fields rs heq
          split at heq
          · rename_i f fs rs' h1 h2 h3
            exact (hno f fs rs' h1 h2 h3).elim
          · cases heq
  | _ => rfl

/-- Phase 2: every rule's decoding refusal, rule by rule. -/
def decodeProblems (rs : List J) : List PolicyErr := rs.filterMap (fun j => errOf (decodeRule j))

/-- The rules that decoded. -/
def decodedRules (rs : List J) : List (Rule Cond) := rs.filterMap (fun j => okOf (decodeRule j))

/-- Phase 3: every definition's refusal, in code point order of the names. -/
def definitionProblems (fs : List (String × String)) : List PolicyErr :=
  (sortByName fs).filterMap (fun d => errOf (parseDef d.1 d.2))

/-- The definitions that parsed, in code point order. -/
def parsedDefs (fs : List (String × String)) : List FieldDef :=
  (sortByName fs).filterMap (fun d => okOf (parseDef d.1 d.2))

/-- Phase 4: every atom's lowering refusal, rule by rule and atom by atom. -/
def loweringProblems (defs : List FieldDef) (rules : List (Rule Cond)) : List PolicyErr :=
  rules.flatMap (fun r => atomProblems defs r.cond.atoms)

/-- Phase 5: rule 6, the fields that allow absence and no rule tests for it, in code point order. -/
def absenceProblems (rules : List (Rule LCond)) (defs : List FieldDef) : List PolicyErr :=
  defs.filterMap (fun d =>
    if d.absentOK && !(rules.any (fun r => r.cond.noneTested.contains d.name)) then some (.absenceUntested d.name)
    else none)

/-- **The stated order** (spec section 4): every problem of a policy image, phase by phase. -/
def policyProblems : Except DocErr J → List PolicyErr
  | .error e => [.unreadable e]
  | .ok j =>
    match imageHead j with
    | .error e => [e]
    | .ok (fs, rs) =>
      let defs := parsedDefs fs
      let rules := decodedRules rs
      decodeProblems rs ++ definitionProblems fs ++ loweringProblems defs rules ++
        (match lowerRules defs rules with
         | .ok lowered => absenceProblems lowered defs
         | .error _ => [])

/-! ## Each phase's first refusal -/

theorem decodeRules_first (rs : List J) : errOf (decodeRules rs) = (decodeProblems rs).head? := by
  induction rs with
  | nil => rfl
  | cons j js ih =>
    simp only [decodeProblems, List.filterMap_cons] at ih ⊢
    unfold decodeRules
    cases h : decodeRule j with
    | error e => rfl
    | ok r =>
      simp only [errOf_ok]
      rw [← ih]
      cases decodeRules js <;> rfl

theorem decodeRules_ok {rs : List J} {rules : List (Rule Cond)} (h : decodeRules rs = .ok rules) :
    decodedRules rs = rules := by
  induction rs generalizing rules with
  | nil => simp [decodeRules] at h; subst h; rfl
  | cons j js ih =>
    unfold decodeRules at h
    cases hj : decodeRule j with
    | error e => rw [hj] at h; cases h
    | ok r =>
      rw [hj] at h
      cases hjs : decodeRules js with
      | error e => rw [hjs] at h; cases h
      | ok rs' =>
        rw [hjs] at h
        cases h
        simp [decodedRules, hj, okOf] at ih ⊢
        exact ih hjs

theorem parseDefList_first (ds : List (String × String)) :
    errOf (parseDefList ds) = (ds.filterMap (fun d => errOf (parseDef d.1 d.2))).head? := by
  induction ds with
  | nil => rfl
  | cons d ds ih =>
    simp only [List.filterMap_cons] at ih ⊢
    unfold parseDefList
    cases h : parseDef d.1 d.2 with
    | error e => rfl
    | ok x =>
      simp only [errOf_ok]
      rw [← ih]
      cases parseDefList ds <;> rfl

theorem parseDefList_ok {ds : List (String × String)} {defs : List FieldDef} (h : parseDefList ds = .ok defs) :
    ds.filterMap (fun d => okOf (parseDef d.1 d.2)) = defs := by
  induction ds generalizing defs with
  | nil => simp [parseDefList] at h; subst h; rfl
  | cons d ds ih =>
    unfold parseDefList at h
    cases hd : parseDef d.1 d.2 with
    | error e => rw [hd] at h; cases h
    | ok x =>
      rw [hd] at h
      cases hds : parseDefList ds with
      | error e => rw [hds] at h; cases h
      | ok xs =>
        rw [hds] at h
        cases h
        simp [hd, okOf]
        exact ih hds

theorem parseDefs_first (fs : List (String × String)) :
    errOf (parseDefs fs) = (definitionProblems fs).head? := parseDefList_first _

theorem lowerRules_first (defs : List FieldDef) (rules : List (Rule Cond)) :
    errOf (lowerRules defs rules) = (loweringProblems defs rules).head? := by
  induction rules with
  | nil => rfl
  | cons r rs ih =>
    simp only [loweringProblems, List.flatMap_cons, List.head?_append] at ih ⊢
    rw [← lowerCond_first_atom defs r.cond, ← ih]
    simp only [lowerRules]
    cases lowerCond defs r.cond <;> cases lowerRules defs rs <;> rfl

theorem checkAbsence_first (rules : List (Rule LCond)) (defs : List FieldDef) :
    errOf (checkAbsence rules defs) = (absenceProblems rules defs).head? := by
  induction defs with
  | nil => rfl
  | cons d ds ih =>
    unfold checkAbsence
    simp only [absenceProblems, List.filterMap_cons] at ih ⊢
    split
    · simp
    · simp [ih]

/-! ## The theorem -/

theorem head?_append_of_ne_none {α : Type} {xs ys : List α} (h : xs.head? ≠ none) :
    (xs ++ ys).head? = xs.head? := by
  cases xs with
  | nil => simp at h
  | cons x xs => rfl

/-- **One cause per refused policy (D7).** The refusal the core computes for a policy image is the first
problem in the order of spec section 4, `policyProblems`: decoding rule by rule, then the definitions in
code point order, then lowering rule by rule and atom by atom, then rule 6. -/
theorem loadPolicy_first_problem (doc : Except DocErr J) :
    errOf (loadPolicy doc) = (policyProblems doc).head? := by
  cases doc with
  | error e => rfl
  | ok j =>
    simp only [loadPolicy, policyProblems]
    rw [show (decodeImage j >>= checkImage) = (match decodeImage j with
          | .error e => .error e | .ok img => checkImage img) from by cases decodeImage j <;> rfl]
    rw [decodeImage_head]
    cases hh : imageHead j with
    | error e => rfl
    | ok head =>
      obtain ⟨fs, rs⟩ := head
      simp only
      cases hr : decodeRules rs with
      | error e =>
        have h1 : (decodeProblems rs).head? = some e := by rw [← decodeRules_first, hr]; rfl
        simp only [errOf_error, List.append_assoc]
        rw [head?_append_of_ne_none (by rw [h1]; simp), h1]
      | ok rules =>
        have hd : decodeProblems rs = [] := by
          have := decodeRules_first rs; rw [hr] at this
          cases hp : decodeProblems rs with
          | nil => rfl
          | cons x xs => rw [hp] at this; cases this
        rw [hd, decodeRules_ok hr]
        simp only [List.nil_append, List.append_assoc]
        unfold checkImage
        cases hf : parseDefs fs with
        | error e =>
          have h2 : (definitionProblems fs).head? = some e := by rw [← parseDefs_first, hf]; rfl
          simp only [bind, Except.bind, errOf_error]
          rw [head?_append_of_ne_none (by rw [h2]; simp), h2]
        | ok defs =>
          have hdp : definitionProblems fs = [] := by
            have := parseDefs_first fs; rw [hf] at this
            cases hp : definitionProblems fs with
            | nil => rfl
            | cons x xs => rw [hp] at this; cases this
          have hpd : parsedDefs fs = defs := parseDefList_ok hf
          rw [hdp, hpd]
          simp only [List.nil_append, bind, Except.bind]
          cases hl : lowerRules defs rules with
          | error e =>
            have h3 : (loweringProblems defs rules).head? = some e := by rw [← lowerRules_first, hl]; rfl
            simp only [errOf_error]
            rw [head?_append_of_ne_none (by rw [h3]; simp), h3]
          | ok lowered =>
            have hlp : loweringProblems defs rules = [] := by
              have := lowerRules_first defs rules; rw [hl] at this
              cases hp : loweringProblems defs rules with
              | nil => rfl
              | cons x xs => rw [hp] at this; cases this
            rw [hlp, List.nil_append, ← checkAbsence_first]
            dsimp only
            cases checkAbsence lowered defs <;> rfl

/-- The refusal of a refused policy is the head of the stated order. -/
theorem policy_cause_is_first (doc : Except DocErr J) (e : PolicyErr) :
    loadPolicy doc = .error e ↔ (policyProblems doc).head? = some e := by
  rw [← loadPolicy_first_problem]
  cases loadPolicy doc <;> simp [errOf]

/-- A policy is accepted exactly when the stated order finds no problem. -/
theorem policy_accepted_iff_no_problem (doc : Except DocErr J) :
    (∃ p, loadPolicy doc = .ok p) ↔ policyProblems doc = [] := by
  rw [← errOf_eq_none, loadPolicy_first_problem]
  cases policyProblems doc <;> simp

/-- In verdict terms: every reading of a refused policy is refused with the stated order's first problem. -/
theorem verdict_policy_cause (image reading : Except DocErr J) (e : PolicyErr) :
    verdict image reading = .refuse (.policy e) ↔ (policyProblems image).head? = some e := by
  rw [policy_refusal_iff, policy_cause_is_first]

end Core
