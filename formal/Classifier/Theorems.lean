-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Hook
import Classifier.Shape
/-!
# The classifier's theorems

What is proved here is proved about the model (Classify.lean, Hook.lean), for every call and every value the
disk observations can take; the Python is held to the model by the differential harness
(formal/diff/classifier_diff.py). docs/design/spec-verified-classifier.md lists the theorems in words.

* Determinism and locality: `classify_local`, `hookCallIn_local`.
* The Bash grammar: `bashArgv_operator`, `splitPlain_outside`, `hook_bash_unknown`, `classify_unknownCall`.
* Read only: `commandClass_read_only`, `classify_read_only`.
* Paths: `classify_traversal`, `classify_glob`, `path_tool_plan`, `run_command_plan`, `pathLike_mem`.
* Kill by pattern: `kill_pkill`, `kill_not_by_pid`, `kill_xargs`, `kill_wrapped`, `killArgsByPid_sound`,
  `classify_kill`.
* Shape: `reading_fields`, `accept_fits`, `boundary_accepts_every_reading`, `decide_never_contract`.
* More the code suggests: `url_network`, `privilege_unknown`, `workspace_program_mutating`,
  `git_unsafe_unknown`, `git_push_remote`, `classify_unknown_tool`, `hook_unknown_tool`, `mcp_unknown_tool`.
-/

namespace Classifier

open Core (J)

/-! ## Merging path facts -/

theorem mergeOne_keeps (r : Reading) (f : PathFacts) :
    (mergeOne r f).tool = r.tool ∧ (mergeOne r f).commandClass = r.commandClass ∧
    (mergeOne r f).killByPattern = r.killByPattern ∧ (mergeOne r f).gitOp = r.gitOp ∧
    (mergeOne r f).remoteClass = r.remoteClass := by
  simp [mergeOne]

/-- Merging path facts changes only the path fields. -/
theorem mergePaths_keeps (r : Reading) (fs : List PathFacts) :
    (mergePaths r fs).tool = r.tool ∧ (mergePaths r fs).commandClass = r.commandClass ∧
    (mergePaths r fs).killByPattern = r.killByPattern ∧ (mergePaths r fs).gitOp = r.gitOp ∧
    (mergePaths r fs).remoteClass = r.remoteClass := by
  induction fs generalizing r with
  | nil => simp [mergePaths]
  | cons f fs ih =>
    have h1 := mergeOne_keeps r f
    have h2 := ih (mergeOne r f)
    simp only [mergePaths, List.foldl_cons] at h2 ⊢
    exact ⟨h2.1.trans h1.1, h2.2.1.trans h1.2.1, h2.2.2.1.trans h1.2.2.1, h2.2.2.2.1.trans h1.2.2.2.1,
      h2.2.2.2.2.trans h1.2.2.2.2⟩

/-- A property every merge step keeps, and that merging one given fact establishes, holds after merging any
list that holds that fact. -/
theorem mergePaths_of_mem {P : Reading → Prop} (keep : ∀ r f, P r → P (mergeOne r f)) {f : PathFacts}
    (make : ∀ r, P (mergeOne r f)) : ∀ {fs : List PathFacts} {r : Reading}, f ∈ fs → P (mergePaths r fs)
  | [], _, h => by cases h
  | g :: gs, r, h => by
    simp only [mergePaths, List.foldl_cons]
    rcases List.mem_cons.mp h with rfl | h'
    · have : ∀ (gs : List PathFacts) (r : Reading), P r → P (gs.foldl mergeOne r) := by
        intro gs; induction gs with
        | nil => intro r hr; exact hr
        | cons x xs ih => intro r hr; exact ih _ (keep r x hr)
      exact this gs _ (make r)
    · exact mergePaths_of_mem keep make h'

theorem merge_traversal {fs : List PathFacts} {f : PathFacts} (hf : f ∈ fs) (ht : f.traversal = true)
    (r : Reading) : (mergePaths r fs).pathTraversal = true :=
  mergePaths_of_mem (P := fun r => r.pathTraversal = true) (by intro r g h; simp [mergeOne, h])
    (by intro r; simp [mergeOne, ht]) hf

theorem merge_glob {fs : List PathFacts} {f : PathFacts} (hf : f ∈ fs) (ht : f.glob = true)
    (r : Reading) : (mergePaths r fs).pathGlob = true :=
  mergePaths_of_mem (P := fun r => r.pathGlob = true) (by intro r g h; simp [mergeOne, h])
    (by intro r; simp [mergeOne, ht]) hf

theorem merge_unknown {fs : List PathFacts} {f : PathFacts} (hf : f ∈ fs) (hu : f.scope = .unknown)
    (r : Reading) : (mergePaths r fs).pathScope = .unknown := by
  refine mergePaths_of_mem (P := fun r => r.pathScope = .unknown) ?_ ?_ hf
  · intro r g h
    simp only [mergeOne, h]
    cases g.scope <;> simp [Scope.rank]
  · intro r
    simp only [mergeOne, hu]
    cases r.pathScope <;> simp [Scope.rank]

/-! ## Determinism and locality -/

theorem pathFacts_congr {f g : Str → Disk} {raw : Str} (h : pathOk raw = true → f raw = g raw) :
    pathFacts f raw = pathFacts g raw := by
  unfold pathFacts
  split
  · rename_i hok; rw [h hok]
  · rfl

theorem classify_eq (disk : Str → Disk) (remotes : List Str) (call : J) :
    classify disk remotes call = mergePaths (plan remotes call).1 ((plan remotes call).2.map (pathFacts disk)) := rfl

/-- **Locality, and so determinism.** The reading is a function of the call, the allowed remotes and the disk's
observations at the paths `diskQueries` names, and of nothing else: two disks that agree there give the same
reading. -/
theorem classify_local {f g : Str → Disk} {remotes : List Str} {call : J}
    (h : ∀ p ∈ diskQueries remotes call, f p = g p) : classify f remotes call = classify g remotes call := by
  rw [classify_eq, classify_eq]
  congr 1
  apply List.map_congr_left
  intro p hp
  exact pathFacts_congr (fun hok => h p (List.mem_filter.mpr ⟨hp, hok⟩))

theorem fromCwd_congr {d₁ d₂ : HookDisk} {cwd w : Str}
    (h : d₁.exists_ (join cwd (wordValue w)) = d₂.exists_ (join cwd (wordValue w))) :
    fromCwd d₁ cwd w = fromCwd d₂ cwd w := by
  unfold fromCwd
  unfold wordValue at h
  split at h <;> simp_all

theorem bashArgv_congr {d₁ d₂ : HookDisk} {command : Option J} {cwd ws : Str}
    (h : ∀ s w0 rest, command = some (.str s) → splitPlain s.toList = some (w0 :: rest) →
      d₁.inside cwd ws = d₂.inside cwd ws ∧ d₁.same cwd ws = d₂.same cwd ws ∧
      ∀ w ∈ rest, d₁.exists_ (join cwd (wordValue w)) = d₂.exists_ (join cwd (wordValue w))) :
    bashArgv d₁ command cwd ws = bashArgv d₂ command cwd ws := by
  match command, h with
  | some (.str s), h =>
    simp only [bashArgv]
    by_cases hop : s.toList.any isShellOperator = true
    · simp [hop]
    · simp only [hop]
      cases hsp : splitPlain s.toList with
      | none => rfl
      | some ws' =>
        cases ws' with
        | nil => rfl
        | cons w0 rest =>
          obtain ⟨hi, hs, he⟩ := h s w0 rest rfl hsp
          have hm : ∀ b : Bool, rest.map (fun w => if b = true then spellWord w else fromCwd d₁ cwd w) =
              rest.map (fun w => if b = true then spellWord w else fromCwd d₂ cwd w) := by
            intro b
            apply List.map_congr_left
            intro w hw
            cases b
            · exact fromCwd_congr (he w hw)
            · rfl
          simp only [hi, hs, hm]
  | none, _ => rfl
  | some .null, _ => rfl
  | some (.bool _), _ => rfl
  | some (.int _), _ => rfl
  | some (.arr _), _ => rfl
  | some (.obj _), _ => rfl

/-- **Locality of the Claude Code mapping.** The call a hook input maps to depends on the disk only through
the facts `hookQueries` names. -/
theorem hookTool_bash (d : HookDisk) (ti : List (String × J)) (cwd ws : Str) :
    hookTool d "Bash" ti cwd ws = match bashArgv d (get? ti "command") cwd ws with
      | some argv => runCall argv
      | none => unknownCall := by
  simp [hookTool, isWriteTool] <;> rfl

theorem hookTool_not_bash (d₁ d₂ : HookDisk) (name : String) (h : name ≠ "Bash") (ti : List (String × J))
    (cwd ws : Str) : hookTool d₁ name ti cwd ws = hookTool d₂ name ti cwd ws := by
  simp [hookTool, h]

theorem hookCallIn_local {d₁ d₂ : HookDisk} {hook : J} {ws : Str}
    (hi : ∀ k ∈ (hookQueries hook ws).inside, d₁.inside k.1 k.2 = d₂.inside k.1 k.2)
    (hs : ∀ k ∈ (hookQueries hook ws).same, d₁.same k.1 k.2 = d₂.same k.1 k.2)
    (he : ∀ p ∈ (hookQueries hook ws).exists_, d₁.exists_ p = d₂.exists_ p) :
    hookCallIn d₁ hook ws = hookCallIn d₂ hook ws := by
  match hook, hi, hs, he with
  | .obj ms, hi, hs, he =>
    simp only [hookQueries] at hi hs he
    simp only [hookCallIn]
    split
    · rename_i name ti hn ht
      simp only [hn, ht] at hi hs he
      by_cases hb : name = "Bash"
      · subst hb
        simp only [show ("Bash" == "Bash") = true from rfl, if_true, bashQueries] at hi hs he
        rw [hookTool_bash, hookTool_bash, bashArgv_congr (d₂ := d₂)]
        intro s w0 rest hc hsp
        rw [hc] at hi hs he
        simp only [hsp] at hi hs he
        refine ⟨hi _ (List.mem_singleton_self _), hs _ (List.mem_singleton_self _), ?_⟩
        intro w hw
        exact he _ (List.mem_map_of_mem hw)
      · exact hookTool_not_bash d₁ d₂ name hb ti _ ws
    · rfl
  | .null, _, _, _ | .bool _, _, _, _ | .int _, _, _, _ | .str _, _, _, _ | .arr _, _, _, _ => rfl

/-! ## The Bash grammar -/

/-- A character the grammar can hold somewhere: inside quotes, or a quote. -/
def inGrammar (c : Char) : Bool := isQuoted '\'' c || c == '\''

theorem inGrammar_of_quoted {q c : Char} (hq : q = '\'' ∨ q = '"') (h : isQuoted q c = true) :
    inGrammar c = true := by
  revert h
  rcases hq with rfl | rfl <;> simp only [inGrammar, isQuoted] <;>
    cases quotedBase c <;> cases (c == '"') <;> cases (c == '\'') <;> decide

theorem quoted_split {q : Char} : ∀ {s t r : Str}, quoted q s = some (t, r) →
    s = t ++ q :: r ∧ ∀ x ∈ t, isQuoted q x = true
  | [], _, _, h => by simp [quoted] at h
  | c :: cs, t, r, h => by
    unfold quoted at h
    split at h
    · rename_i hc
      simp only [Option.some.injEq, Prod.mk.injEq] at h
      obtain ⟨rfl, rfl⟩ := h
      simp [beq_iff_eq.mp hc]
    · split at h
      · rename_i _ hq
        cases hrec : quoted q cs with
        | none => simp [hrec] at h
        | some p =>
          rw [hrec] at h
          simp only [Option.map_some, Option.some.injEq, Prod.mk.injEq] at h
          obtain ⟨rfl, rfl⟩ := h
          obtain ⟨h1, h2⟩ := quoted_split hrec
          refine ⟨by simp [h1], ?_⟩
          intro x hx
          rcases List.mem_cons.mp hx with rfl | hx
          · exact hq
          · exact h2 x hx
      · cases h

theorem splitPlainGo_outside : ∀ (fuel : Nat) (cur : Option Str) (s : Str),
    (∃ x ∈ s, inGrammar x = false) → splitPlainGo fuel cur s = none
  | _, _, [], ⟨_, hx, _⟩ => by cases hx
  | 0, _, _ :: _, _ => rfl
  | fuel + 1, cur, c :: cs, ⟨x, hx, hbad⟩ => by
    unfold splitPlainGo
    have hc : x = c ∨ x ∈ cs := List.mem_cons.mp hx
    split
    · rename_i hb
      have : x ∈ cs := by
        rcases hc with rfl | h
        · exfalso; simp [inGrammar, isQuoted, quotedBase, hb] at hbad
        · exact h
      split <;> simp [splitPlainGo_outside fuel none cs ⟨x, this, hbad⟩]
    · split
      · rename_i _ hp
        have : x ∈ cs := by
          rcases hc with rfl | h
          · exfalso; simp [inGrammar, isQuoted, quotedBase, hp] at hbad
          · exact h
        exact splitPlainGo_outside fuel _ cs ⟨x, this, hbad⟩
      · split
        · rename_i _ _ hq
          split
          · rename_i text rest hqs
            obtain ⟨hcs, ht⟩ := quoted_split hqs
            have hq' : c = '\'' ∨ c = '"' := by simpa using hq
            rcases hc with rfl | h
            · exfalso; rcases hq' with rfl | rfl <;> simp [inGrammar, isQuoted, quotedBase, isPlain, isBlank] at hbad
            · rw [hcs] at h
              rcases List.mem_append.mp h with h | h
              · exfalso; have := inGrammar_of_quoted hq' (ht x h); simp [this] at hbad
              · rcases List.mem_cons.mp h with rfl | h
                · exfalso; rcases hq' with rfl | rfl <;> simp [inGrammar, isQuoted, quotedBase, isPlain, isBlank] at hbad
                · exact splitPlainGo_outside fuel _ rest ⟨x, h, hbad⟩
          · rfl
        · rfl

/-- **A character outside the grammar makes the command unreadable.** -/
theorem splitPlain_outside {s : Str} (h : ∃ x ∈ s, inGrammar x = false) : splitPlain s = none :=
  splitPlainGo_outside _ _ _ h

theorem splitPlainGo_chars (P : Char → Prop) : ∀ (fuel : Nat) (cur : Option Str) (s : Str) (ws : List Str),
    splitPlainGo fuel cur s = some ws → (∀ x ∈ cur.getD [], P x) → (∀ x ∈ s, P x) → ∀ w ∈ ws, ∀ x ∈ w, P x
  | fuel, cur, [], ws, h, hc, _ => by
    cases fuel <;> cases cur <;> simp [splitPlainGo] at h <;> subst h <;> simp_all
  | 0, _, _ :: _, _, h, _, _ => by simp [splitPlainGo] at h
  | fuel + 1, cur, c :: cs, ws, h, hc, hs => by
    have hcs : ∀ x ∈ cs, P x := fun x hx => hs x (List.mem_cons_of_mem _ hx)
    unfold splitPlainGo at h
    split at h
    · cases cur with
      | none => exact splitPlainGo_chars P fuel none cs ws h (by simp) hcs
      | some w =>
        simp only at h
        cases hrec : splitPlainGo fuel none cs with
        | none => rw [hrec] at h; cases h
        | some ws' =>
          rw [hrec] at h
          simp only [Option.map_some, Option.some.injEq] at h
          subst h
          intro v hv x hx
          rcases List.mem_cons.mp hv with rfl | hv
          · exact hc x hx
          · exact splitPlainGo_chars P fuel none cs ws' hrec (by simp) hcs v hv x hx
    · split at h
      · refine splitPlainGo_chars P fuel _ cs ws h ?_ hcs
        intro x hx
        simp only [Option.getD_some, List.mem_append, List.mem_singleton] at hx
        rcases hx with hx | rfl
        · exact hc x hx
        · exact hs x (List.mem_cons_self ..)
      · split at h
        · split at h
          · rename_i text rest hq
            obtain ⟨hsplit, _⟩ := quoted_split hq
            have hrest : ∀ x ∈ rest, P x := fun x hx => hcs x (by rw [hsplit]; simp [hx])
            refine splitPlainGo_chars P fuel _ rest ws h ?_ hrest
            intro x hx
            simp only [Option.getD_some, List.mem_append] at hx
            rcases hx with hx | hx
            · exact hc x hx
            · exact hcs x (by rw [hsplit]; simp [hx])
          · cases h
        · cases h

/-- **The grammar's words are the command's own characters**: no word holds a character the command did not,
so with the operator check (`bashArgv_operator`) no word the mapping reads holds a shell operator. -/
theorem splitPlain_words_chars {s : Str} {ws : List Str} (h : splitPlain s = some ws) :
    ∀ w ∈ ws, ∀ x ∈ w, x ∈ s :=
  splitPlainGo_chars (· ∈ s) _ none s ws h (by simp) (fun _ hx => hx)

/-- **A shell operator anywhere makes the command unreadable.** -/
theorem bashArgv_operator (d : HookDisk) (s : String) (cwd ws : Str)
    (h : ∃ x ∈ s.toList, isShellOperator x = true) : bashArgv d (some (.str s)) cwd ws = none := by
  have : s.toList.any isShellOperator = true := List.any_eq_true.mpr h
  simp [bashArgv, this]

theorem bashArgv_outside (d : HookDisk) (s : String) (cwd ws : Str)
    (h : ∃ x ∈ s.toList, inGrammar x = false) : bashArgv d (some (.str s)) cwd ws = none := by
  unfold bashArgv
  simp only
  split
  · rfl
  · rw [splitPlain_outside h]

/-- A later word that starts with `~` or holds `{` (home or brace expansion) makes the command unreadable. -/
theorem bashArgv_tilde_brace (d : HookDisk) (s : String) (cwd ws w0 : Str) (rest : List Str)
    (hs : splitPlain s.toList = some (w0 :: rest)) (hw : ∃ w ∈ rest, startsWith w (lit "~") = true ∨ w.contains '{' = true) :
    bashArgv d (some (.str s)) cwd ws = none := by
  have hany : (rest.any fun w => startsWith w (lit "~") || w.contains '{') = true := by
    obtain ⟨w, hw, hc⟩ := hw
    exact List.any_eq_true.mpr ⟨w, hw, by rcases hc with h | h <;> simp only [h, Bool.or_true, Bool.true_or]⟩
  simp only [bashArgv, hs, hany, if_true, ite_self]

theorem classify_unknownCall (disk : Str → Disk) (remotes : List Str) :
    classify disk remotes unknownCall = unknownReading := by
  rfl

/-- **A Bash command with a shell operator or a character outside the grammar maps to the unknown call**, whose
reading is the unknown reading (`classify_unknownCall`). -/
theorem hook_bash_unknown (d : HookDisk) (ms ti : List (String × J)) (s : String) (ws : Str)
    (hn : get? ms "tool_name" = some (.str "Bash")) (ht : get? ms "tool_input" = some (.obj ti))
    (hc : get? ti "command" = some (.str s))
    (hbad : ∃ x ∈ s.toList, isShellOperator x = true ∨ inGrammar x = false) :
    hookCallIn d (.obj ms) ws = unknownCall := by
  simp only [hookCallIn, hn, ht, hookTool_bash, hc]
  obtain ⟨x, hx, hop | hg⟩ := hbad
  · rw [bashArgv_operator d s _ ws ⟨x, hx, hop⟩]
  · rw [bashArgv_outside d s _ ws ⟨x, hx, hg⟩]

/-! ## Read only -/

/-- **Nothing outside the model's `READ_ONLY` list is read only.** This is a fact about the model's own list, not
a proof that a listed program cannot write: `prismpath/tests/test_read_only_runs.py` runs every listed program to
check that. An argv reads `read_only` only when its program (the
bare word, or the base name of a path in a system directory) is in `READ_ONLY`, is in neither `NETWORK` nor
`PRIVILEGE`, is not git, and no argument holds a URL. -/
theorem commandClass_read_only {argv : List Str} (h : commandClass argv = .read_only) :
    ∃ first args base, argv = first :: args ∧ program first = some base ∧ READ_ONLY.contains base = true ∧
      NETWORK.contains base = false ∧ PRIVILEGE.contains base = false ∧ base ≠ lit "git" ∧
      args.any hasURL = false := by
  cases argv with
  | nil => simp [commandClass] at h
  | cons first args =>
    refine ⟨first, args, ?_⟩
    simp only [commandClass] at h
    cases hp : program first with
    | none => rw [hp] at h; cases h
    | some base =>
      rw [hp] at h
      simp only at h
      refine ⟨base, rfl, rfl, ?_⟩
      by_cases h1 : (base.isEmpty || PRIVILEGE.contains base) = true
      · simp only [h1, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h1
      simp only [h1, Bool.false_eq_true, if_false] at h
      by_cases h2 : (base == lit "git") = true
      · simp only [h2, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h2
      simp only [h2, Bool.false_eq_true, if_false] at h
      by_cases h3 : (NETWORK.contains base || args.any hasURL) = true
      · simp only [h3, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h3
      simp only [h3, Bool.false_eq_true, if_false] at h
      by_cases h4 : installerFetches base args = true
      · simp only [h4, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h4
      simp only [h4, Bool.false_eq_true, if_false] at h
      by_cases h5 : ((base == lit "python" || base == lit "python3") && args.take 2 == [lit "-m", lit "pip"]) = true
      · simp only [h5, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h5
      simp only [h5, Bool.false_eq_true, if_false] at h
      by_cases h6 : (base == lit "find" && args.any (fun a => FIND_EFFECTS.contains a)) = true
      · simp only [h6, if_true] at h; cases h
      simp only [Bool.not_eq_true] at h6
      simp only [h6, Bool.false_eq_true, if_false] at h
      by_cases h7 : READ_ONLY.contains base = true
      · simp only [Bool.or_eq_false_iff] at h1 h3
        exact ⟨h7, h3.1, h1.2, fun e => by simp [e] at h2, h3.2⟩
      · simp only [h7, Bool.false_eq_true, if_false] at h
        split at h <;> cases h

theorem runPlan_keeps (remotes : List Str) (argv : List Str) :
    (runPlan remotes argv).1.tool = .run_command ∧ (runPlan remotes argv).1.commandClass = commandClass argv ∧
    (runPlan remotes argv).1.killByPattern = killByPattern argv := by
  simp only [runPlan]
  split <;> exact ⟨rfl, rfl, rfl⟩

theorem plan_commandClass (remotes : List Str) (call : J) :
    (plan remotes call).1.commandClass = .none ∨ (plan remotes call).1.commandClass = .unknown ∨
      ∃ argv, (plan remotes call).1.commandClass = commandClass argv := by
  simp only [plan]
  repeat' split
  all_goals first
    | (left; rfl)
    | (right; left; rfl)
    | (right; right; exact ⟨_, (runPlan_keeps _ _).2.1⟩)

/-- At the level of the reading: a reading whose command class is `read_only` came from an argv the read only
theorem describes. -/
theorem classify_read_only {disk : Str → Disk} {remotes : List Str} {call : J}
    (h : (classify disk remotes call).commandClass = .read_only) :
    ∃ argv, commandClass argv = .read_only := by
  rw [classify_eq, (mergePaths_keeps _ _).2.1] at h
  rcases plan_commandClass remotes call with h' | h' | ⟨argv, h'⟩
  · rw [h'] at h; cases h
  · rw [h'] at h; cases h
  · exact ⟨argv, h' ▸ h⟩

/-- A privilege program never reads as anything but unknown. -/
theorem privilege_unknown {first : Str} {args : List Str} {base : Str} (hp : program first = some base)
    (h : PRIVILEGE.contains base = true) : commandClass (first :: args) = .unknown := by
  simp only [commandClass, hp, h, Bool.or_true, if_true]

/-- **A URL in any argument is network**, whatever the program, unless the program is a privilege program
(unknown), git (read by its own subcommand) or a program of the workspace (mutating). -/
theorem url_network {first : Str} {args : List Str} {base : Str} (hp : program first = some base)
    (hne : base ≠ []) (hpriv : PRIVILEGE.contains base = false) (hgit : base ≠ lit "git")
    (hu : args.any hasURL = true) : commandClass (first :: args) = .network := by
  have hb : base.isEmpty = false := by cases base <;> simp_all
  have hg : (base == lit "git") = false := by simpa using hgit
  simp only [commandClass, hp, hb, hpriv, Bool.or_false, Bool.false_eq_true, if_false, hg, hu, Bool.or_true, if_true]

/-- A program named by a path outside the system directories is a program of the workspace: mutating. -/
theorem workspace_program_mutating {first : Str} {args : List Str} (hslash : first.contains '/' = true)
    (hsys : startsWith first (lit "/") = false ∨ SYSTEM_DIRS.contains (dirname first) = false) :
    commandClass (first :: args) = .mutating := by
  have hc : (startsWith first (lit "/") && SYSTEM_DIRS.contains (dirname first)) = false := by
    rcases hsys with h | h
    · simp only [h, Bool.false_and]
    · simp only [h, Bool.and_false]
  have : program first = none := by
    simp only [program, hc, Bool.false_eq_true, if_false, hslash, if_true]
  simp only [commandClass, this]

/-! ## Paths -/

theorem pathFacts_traversal (disk : Str → Disk) {raw : Str} (h : isTraversal raw = true) :
    (pathFacts disk raw).traversal = true ∨ (pathFacts disk raw).scope = .unknown := by
  unfold pathFacts; split <;> simp [h]

theorem pathFacts_glob (disk : Str → Disk) {raw : Str} (h : isGlob raw = true) :
    (pathFacts disk raw).glob = true ∨ (pathFacts disk raw).scope = .unknown := by
  unfold pathFacts; split <;> simp [h]

/-- **A path with a `..` component reads as traversal**: any path the call names (`plan`'s list) that has a
`..` component gives a reading with `path_traversal`, or, when the path fails the syntactic check, the unknown
scope (refused as unclassifiable). -/
theorem classify_traversal {disk : Str → Disk} {remotes : List Str} {call : J} {p : Str}
    (hp : p ∈ (plan remotes call).2) (ht : isTraversal p = true) :
    (classify disk remotes call).pathTraversal = true ∨ (classify disk remotes call).pathScope = .unknown := by
  rw [classify_eq]
  have hm : pathFacts disk p ∈ (plan remotes call).2.map (pathFacts disk) := List.mem_map_of_mem hp
  rcases pathFacts_traversal disk ht with h | h
  · exact Or.inl (merge_traversal hm h _)
  · exact Or.inr (merge_unknown hm h _)

/-- **A glob character gives path_glob**, in the same sense. -/
theorem classify_glob {disk : Str → Disk} {remotes : List Str} {call : J} {p : Str}
    (hp : p ∈ (plan remotes call).2) (hg : isGlob p = true) :
    (classify disk remotes call).pathGlob = true ∨ (classify disk remotes call).pathScope = .unknown := by
  rw [classify_eq]
  have hm : pathFacts disk p ∈ (plan remotes call).2.map (pathFacts disk) := List.mem_map_of_mem hp
  rcases pathFacts_glob disk hg with h | h
  · exact Or.inl (merge_glob hm h _)
  · exact Or.inr (merge_unknown hm h _)

theorem isGlob_of_char {raw : Str} {c : Char} (hc : c ∈ raw) (hg : isGlobChar c = true) : isGlob raw = true := by
  simp only [isGlob, Bool.or_eq_true, List.any_eq_true]
  exact Or.inl ⟨c, hc, hg⟩

theorem isTraversal_of_component {raw : Str} (h : lit ".." ∈ splitSlash raw) : isTraversal raw = true := by
  simp [isTraversal, h]

/-- The path tools name exactly their path. -/
theorem path_tool_plan (remotes : List Str) (t : String) (ht : t = "list_dir" ∨ t = "read_file" ∨ t = "delete_path")
    (p : String) : plan remotes (.obj [("tool", .str t), ("args", .obj [("path", .str p)])]) =
      ({ tool := toolOf t }, [p.toList]) := by
  rcases ht with rfl | rfl | rfl <;> rfl

theorem write_plan (remotes : List Str) (p c : String) :
    plan remotes (.obj [("tool", .str "write_file"), ("args", .obj [("path", .str p), ("content", .str c)])]) =
      ({ tool := .write_file }, [p.toList]) := rfl

/-- Every argument that is not an option is a path the command names (and every argument after `--`). -/
theorem pathLike_mem : ∀ (after : Bool) (args : List Str) (a : Str), a ∈ args → startsWith a (lit "-") = false →
    a ∈ pathLike after args
  | _, [], _, h, _ => by cases h
  | true, x :: xs, a, h, hd => by
    rcases List.mem_cons.mp h with rfl | h
    · simp [pathLike]
    · simp only [pathLike]; exact List.mem_cons_of_mem _ (pathLike_mem true xs a h hd)
  | false, x :: xs, a, h, hd => by
    rcases List.mem_cons.mp h with rfl | h
    · have hne : (a == lit "--") = false := by
        cases hh : (a == lit "--")
        · rfl
        · rw [beq_iff_eq.mp hh] at hd; cases hd
      simp [pathLike, hne, hd]
    · have ih := pathLike_mem false xs a h hd
      have ih' := pathLike_mem true xs a h hd
      simp only [pathLike]
      repeat' split
      all_goals first
        | exact ih'
        | exact ih
        | exact List.mem_cons_of_mem _ ih

theorem runCall_plan (remotes : List Str) (xs : List J) (argv : List Str) (h : argvOf? xs = some argv) :
    plan remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])]) = runPlan remotes argv := by
  simp [plan, get?, Core.field?, toolOf, schemaOk, schema, has, VKind.ok, h]

/-- A run_command argv that is not git names every argument that is not an option as a path. -/
theorem run_command_plan {remotes : List Str} {argv : List Str} (hg : commandClass argv ≠ .git) {a : Str}
    (ha : a ∈ argv.drop 1) (hd : startsWith a (lit "-") = false) : a ∈ (runPlan remotes argv).2 := by
  have : (commandClass argv == .git) = false := by simpa using hg
  simp only [runPlan, this, Bool.false_eq_true, if_false]
  exact pathLike_mem false _ a ha hd

/-! ## Kill by pattern -/

theorem killByPattern_cons (a0 : Str) (args : List Str) :
    killByPattern (a0 :: args) =
      ((basename a0 == lit "pkill" || basename a0 == lit "killall") ||
       (basename a0 == lit "kill" && !killArgsByPid args) ||
       (basename a0 == lit "xargs" && args.contains (lit "kill")) ||
       (WRAPPERS.contains (basename a0) && args.any argKills)) := by
  simp only [killByPattern]
  cases h1 : (basename a0 == lit "pkill" || basename a0 == lit "killall") <;>
  cases h2 : (basename a0 == lit "kill" && !killArgsByPid args) <;>
  cases h3 : (basename a0 == lit "xargs" && args.contains (lit "kill")) <;>
  cases h4 : WRAPPERS.contains (basename a0) <;> simp

theorem kill_pkill (a0 : Str) (args : List Str) (h : basename a0 = lit "pkill" ∨ basename a0 = lit "killall") :
    killByPattern (a0 :: args) = true := by
  rw [killByPattern_cons]
  rcases h with h | h <;> simp [h]

/-- `kill` whose targets are not all process ids (a `-1`, a `0`, a name, a job, nothing at all). -/
theorem kill_not_by_pid (a0 : Str) (args : List Str) (h : basename a0 = lit "kill") (hp : killArgsByPid args = false) :
    killByPattern (a0 :: args) = true := by
  rw [killByPattern_cons, h, hp]
  simp

theorem kill_xargs (a0 : Str) (args : List Str) (h : basename a0 = lit "xargs") (hk : lit "kill" ∈ args) :
    killByPattern (a0 :: args) = true := by
  have : args.contains (lit "kill") = true := List.elem_iff.mpr hk
  rw [killByPattern_cons, h, this]
  simp

/-- A kill written in an argument of a program that runs other programs (a shell's `-c` text, env, timeout,
nohup, sudo...): a `pkill` or `killall` word, or a `kill` word not followed only by process ids. -/
theorem kill_wrapped (a0 : Str) (args : List Str) (hw : WRAPPERS.contains (basename a0) = true) {a : Str}
    (ha : a ∈ args) (hk : argKills a = true) : killByPattern (a0 :: args) = true := by
  have hany : args.any argKills = true := List.any_eq_true.mpr ⟨a, ha, hk⟩
  rw [killByPattern_cons, hw, hany]
  simp

theorem argKills_word {a : Str} (h : hasKillWord a = true) : argKills a = true := by
  simp [argKills, h]

theorem argKills_inner {a cmd : Str} (hc : cmd ∈ splitBy isShellSeparator a) (h : innerKill (pyWords cmd) = true) :
    argKills a = true := by
  simp only [argKills, Bool.or_eq_true, List.any_eq_true]
  exact Or.inr ⟨cmd, hc, h⟩

theorem innerKill_of {ws : List Str} {pre post : List Str} (h : ws = pre ++ lit "kill" :: post)
    (hp : killArgsByPid post = false) : innerKill ws = true := by
  subst h
  induction pre with
  | nil => simp [innerKill, hp]
  | cons w ws ih => simp [innerKill, ih]

/-- **A kill that is not by pattern names process ids only**: `killArgsByPid` holds exactly of a non empty list of
positive process ids, after at most one signal (`-SIGNAL`, or `-s` and a word). -/
theorem killArgsByPid_sound {args : List Str} (h : killArgsByPid args = true) :
    ∃ targets, targets ≠ [] ∧ (∀ t ∈ targets, isPid t = true) ∧
      (args = targets ∨ (∃ s, isSignal s = true ∧ args = s :: targets) ∨ ∃ s, args = lit "-s" :: s :: targets) := by
  match args, h with
  | [], h => simp [killArgsByPid] at h
  | [a], h =>
    by_cases hs : isSignal a = true
    · simp [killArgsByPid, hs] at h
    · simp only [killArgsByPid, hs, Bool.false_eq_true, if_false, Bool.and_eq_true, Bool.not_eq_true',
        List.isEmpty_eq_false_iff, List.all_eq_true] at h
      exact ⟨[a], by simp, h.2, Or.inl rfl⟩
  | a :: b :: r, h =>
    by_cases h1 : (a == lit "-s") = true
    · simp only [killArgsByPid, h1, if_true, Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff,
        List.all_eq_true] at h
      exact ⟨r, h.1, h.2, Or.inr (Or.inr ⟨b, by rw [beq_iff_eq.mp h1]⟩)⟩
    · simp only [Bool.not_eq_true] at h1
      by_cases h2 : isSignal a = true
      · simp only [killArgsByPid, h1, h2, Bool.false_eq_true, if_false, if_true, Bool.and_eq_true,
          Bool.not_eq_true', List.isEmpty_eq_false_iff, List.all_eq_true] at h
        exact ⟨b :: r, by simp, h.2, Or.inr (Or.inl ⟨a, h2, rfl⟩)⟩
      · simp only [Bool.not_eq_true] at h2
        simp only [killArgsByPid, h1, h2, Bool.false_eq_true, if_false, Bool.and_eq_true, Bool.not_eq_true',
          List.isEmpty_eq_false_iff, List.all_eq_true] at h
        exact ⟨a :: b :: r, by simp, h.2, Or.inl rfl⟩

/-- At the level of the reading: a well formed run_command call reads `kill_by_pattern` exactly when its argv
does. -/
theorem classify_kill (disk : Str → Disk) (remotes : List Str) (xs : List J) (argv : List Str)
    (h : argvOf? xs = some argv) :
    (classify disk remotes (.obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr xs)])])).killByPattern =
      killByPattern argv := by
  rw [classify_eq, (mergePaths_keeps _ _).2.2.1, runCall_plan remotes xs argv h]
  exact (runPlan_keeps _ _).2.2

/-- Only a command can kill: a reading with `kill_by_pattern` is a run_command reading. -/
theorem kill_only_run_command {disk : Str → Disk} {remotes : List Str} {call : J}
    (h : (classify disk remotes call).killByPattern = true) : (classify disk remotes call).tool = .run_command := by
  rw [classify_eq, (mergePaths_keeps _ _).2.2.1] at h
  rw [classify_eq, (mergePaths_keeps _ _).1]
  revert h
  simp only [plan]
  repeat' split
  all_goals first
    | (intro h; cases h)
    | (intro _; exact (runPlan_keeps _ _).1)

/-! ## git -/

/-- An option that runs a program or moves the repository (`--exec`, `--upload-pack`, `-c`, `--git-dir`, `-C`, ...)
makes the operation unknown, which the policies refuse. -/
theorem git_unsafe_unknown (remotes : List Str) (s : Str) (args : List Str) (hs : s.isEmpty = false)
    (hd : startsWith s (lit "-") = false) (hu : args.any unsafeOption = true) :
    gitPlan remotes (some s) (some args) = (.unknown, .none, []) := by
  simp only [gitPlan, hs, hd, Bool.or_false, Bool.false_eq_true, if_false, hu, if_true]

/-- A push goes to an allowed remote only when its first remote word is one of `remotes` (`origin` by default). -/
theorem git_push_remote (remotes : List Str) (args : List Str) (hu : args.any unsafeOption = false) :
    gitPlan remotes (some (lit "push")) (some args) =
      (.push, (if remotes.contains (((args.filter (fun a => !startsWith a (lit "-"))).head?).getD (lit "origin"))
        then .allowed else .other), []) := by
  have h1 : (lit "push").isEmpty = false := rfl
  have h2 : startsWith (lit "push") (lit "-") = false := by decide
  simp only [gitPlan, h1, h2, hu, Bool.or_false, Bool.false_eq_true, if_false, beq_self_eq_true, if_true]

/-! ## Unknown tools -/

theorem classify_unknown_tool (disk : Str → Disk) (remotes : List Str) (ms : List (String × J)) (name : String)
    (hn : get? ms "tool" = some (.str name)) (ht : toolOf name = .unknown) :
    classify disk remotes (.obj ms) = unknownReading := by
  rw [classify_eq]
  simp only [plan, hn, ht]
  split <;> rfl

/-- Every Claude Code tool the mapping does not read (WebFetch, Task, every `mcp__*` tool, any tool not yet
invented) is the unknown call. -/
theorem hook_unknown_tool (d : HookDisk) (name : String) (ti : List (String × J)) (cwd ws : Str)
    (h : name ∉ ["Read", "Write", "Edit", "MultiEdit", "NotebookEdit", "Glob", "Grep", "LS", "Bash"]) :
    hookTool d name ti cwd ws = unknownCall := by
  simp only [List.mem_cons, List.not_mem_nil, or_false, not_or] at h
  obtain ⟨h1, h2, h3, h4, h5, h6, h7, h8, h9⟩ := h
  simp [hookTool, isWriteTool, h1, h2, h3, h4, h5, h6, h7, h8, h9]

/-- An MCP tool that is neither a classifier tool nor a known filesystem tool is the unknown call. -/
theorem mcp_unknown_tool (ps am : List (String × J)) (name : String) (cwd : Str)
    (hn : get? ps "name" = some (.str name)) (ha : (get? ps "arguments").getD (.obj []) = .obj am)
    (ht : TOOLS.contains name.toList = false) (hf : fsTool name = none) :
    mcpCall (.obj ps) cwd = unknownCall := by
  simp only [mcpCall, hn, ha, ht, Bool.false_eq_true, if_false, hf]

/-! ## The shape of every reading -/

/-- Every reading holds the fourteen fields the agent policies define, in canonical order, and its version. -/
theorem reading_fields (r : Reading) :
    r.members.map (·.1) = ["classifier_version", "command_class", "git_op", "kill_by_pattern", "net_dest",
      "path_control", "path_glob", "path_in_toolchain", "path_scope", "path_symlink", "path_traversal", "proc_class",
      "remote_class", "tool"] ∧
    Core.field? r.members "classifier_version" = some (.int CLASSIFIER_VERSION) := ⟨rfl, rfl⟩

theorem field_category (r : Reading) : ∀ n ∈ categoryFields, ∃ s, Core.field? r.members n = some (.str s) := by
  intro n hn
  simp only [categoryFields, List.mem_cons, List.not_mem_nil, or_false] at hn
  rcases hn with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;> exact ⟨_, rfl⟩

theorem field_bool (r : Reading) : ∀ n ∈ boolFields, ∃ b, Core.field? r.members n = some (.bool b) := by
  intro n hn
  simp only [boolFields, List.mem_cons, List.not_mem_nil, or_false] at hn
  rcases hn with rfl | rfl | rfl | rfl | rfl | rfl <;> exact ⟨_, rfl⟩

theorem field_other (r : Reading) (n : String) (h0 : n ≠ "classifier_version") (hc : n ∉ categoryFields)
    (hb : n ∉ boolFields) : Core.field? r.members n = none := by
  simp only [categoryFields, boolFields, List.mem_cons, List.not_mem_nil, or_false, not_or] at hc hb
  have : r.members.find? (fun m => m.1 == n) = none := by
    rw [List.find?_eq_none]
    intro m hm
    simp only [Reading.members, List.mem_cons, List.not_mem_nil, or_false] at hm
    rcases hm with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
      simp only [beq_iff_eq] <;> intro e <;> simp_all
  simp only [Core.field?, this]

/-- A definition that fits accepts the value every reading holds for its name. -/
theorem accept_fits (r : Reading) (d : Core.FieldDef) (h : fits d = true) :
    ∃ v, Core.acceptField d (Core.field? r.members d.name) = .ok v := by
  unfold fits at h
  by_cases h0 : d.name = "classifier_version"
  · simp only [h0, beq_self_eq_true, if_true, Bool.and_eq_true, beq_iff_eq, decide_eq_true_eq] at h
    obtain ⟨⟨hk, hlo⟩, hhi⟩ := h
    refine ⟨some (.int CLASSIFIER_VERSION), ?_⟩
    rw [h0, (reading_fields r).2]
    simp only [Core.acceptField, hk]
    have : ((CLASSIFIER_VERSION : Int) < d.lo || (CLASSIFIER_VERSION : Int) > d.hi) = false := by
      simp only [Bool.or_eq_false_iff, decide_eq_false_iff_not]; omega
    simp [this]
  · have h0' : (d.name == "classifier_version") = false := by simpa using h0
    simp only [h0', Bool.false_eq_true, if_false] at h
    by_cases hc : categoryFields.contains d.name = true
    · simp only [hc, if_true, beq_iff_eq] at h
      obtain ⟨s, hs⟩ := field_category r d.name (List.elem_iff.mp hc)
      exact ⟨some (.str s), by rw [hs]; simp [Core.acceptField, h]⟩
    · simp only [Bool.not_eq_true] at hc
      simp only [hc, Bool.false_eq_true, if_false] at h
      by_cases hb : boolFields.contains d.name = true
      · simp only [hb, if_true, beq_iff_eq] at h
        obtain ⟨b, hs⟩ := field_bool r d.name (List.elem_iff.mp hb)
        exact ⟨some (.bool b), by rw [hs]; simp [Core.acceptField, h]⟩
      · simp only [Bool.not_eq_true] at hb
        simp only [hb, Bool.false_eq_true, if_false] at h
        have hc' : d.name ∉ categoryFields := fun m => absurd m (by simpa using hc)
        have hb' : d.name ∉ boolFields := fun m => absurd m (by simpa using hb)
        rw [field_other r d.name h0 hc' hb']
        exact ⟨none, by simp [Core.acceptField, h]⟩

theorem firstRefused_fits (r : Reading) : ∀ (defs : List Core.FieldDef), defs.all fits = true →
    Core.firstRefused r.members defs = none
  | [], _ => rfl
  | d :: ds, h => by
    simp only [List.all_cons, Bool.and_eq_true] at h
    obtain ⟨v, hv⟩ := accept_fits r d h.1
    simp only [Core.firstRefused, hv]
    exact firstRefused_fits r ds h.2

/-- **The core's boundary never refuses a classifier reading for its shape.** For a policy whose field definitions
all fit (the three shipped agent policies do: the oracle's `--policy` mode computes `fitsAll` on each image, and
the differential harness requires it), the system boundary accepts every reading the classifier can make. -/
theorem boundary_accepts_every_reading (p : Core.Checked) (h : fitsAll p.defs = true) (r : Reading) :
    Core.systemBoundary p r.members = none :=
  firstRefused_fits r p.defs h

/-- So the verdict on a reading is a route or no match, never a contract violation. -/
theorem decide_never_contract (p : Core.Checked) (h : fitsAll p.defs = true) (r : Reading) :
    ∀ f e, Core.decideReading p (.ok r.json) ≠ .refuse (.contract f e) := by
  intro f e
  have hb : Core.firstRefused r.members p.defs = none := firstRefused_fits r p.defs h
  simp only [Reading.json, Core.decideReading, hb]
  split <;> simp

end Classifier
