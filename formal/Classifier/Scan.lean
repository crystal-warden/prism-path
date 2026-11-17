-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Hook
/-!
# The hazard scan of a Bash command the grammar does not read

`claude_code.hazard_scan`: a Bash command that maps to the unknown call is scanned on its raw text for evidence
of a hazard, by rules stated on the text alone; evidence becomes reading fields the refusal rules fire on before
the unclassifiable escalation, and no evidence leaves the unknown reading as it was (docs/design/spec-verified-
classifier.md section 4.1). The text is first stripped of backslashes and quotes (`strip`).

* kill: an ASCII word (`asciiWords`, maximal runs of letters, digits and `_`) that is `pkill`, `killall` or `kill`;
* network: an ASCII word in `NETWORK`, or a URL scheme (`hasURL`);
* outside: a token (`tokens`, split at Python whitespace, shell operators and `= : , { }`) that starts with `~`,
  or starts with `/` and is neither the workspace nor below it;
* traversal: a token with a `..` component; toolchain: a token with a `.toolchain` component.

`hookReading` is `claude_code.hook_reading`.
-/

namespace Classifier

open Core (J)

def isStripped (c : Char) : Bool := c == '\\' || c == '\'' || c == '"'

def strip (s : Str) : Str := s.filter (fun c => !isStripped c)

def asciiWords (s : Str) : List Str := (splitBy (fun c => !isAsciiWord c) s).filter (fun w => !w.isEmpty)

def isTokenSep (c : Char) : Bool :=
  isPyWs c || isShellOperator c || c == '=' || c == ':' || c == ',' || c == '{' || c == '}'

def tokens (s : Str) : List Str := (splitBy isTokenSep s).filter (fun w => !w.isEmpty)

def killEvidence (t : Str) : Bool :=
  (asciiWords t).any (fun w => w == lit "pkill" || w == lit "killall" || w == lit "kill")

def networkEvidence (t : Str) : Bool := (asciiWords t).any (fun w => NETWORK.contains w) || hasURL t

def outsideToken (ws tok : Str) : Bool :=
  startsWith tok (lit "~") || (startsWith tok (lit "/") && !(tok == ws || startsWith tok (ws ++ ['/'])))

def outsideEvidence (ws t : Str) : Bool := (tokens t).any (outsideToken ws)
def traversalEvidence (t : Str) : Bool := (tokens t).any (fun tok => (splitSlash tok).contains (lit ".."))
def toolchainEvidence (t : Str) : Bool := (tokens t).any (fun tok => (splitSlash tok).contains (lit ".toolchain"))

/-- The reading the scan gives for the evidence found. -/
def scanOf (kill net out trav tool : Bool) : Reading :=
  { tool := .run_command, killByPattern := kill,
    commandClass := if net then .network else if out || trav || tool then .mutating else .unknown,
    pathScope := if out then .outside else .none, pathTraversal := trav, pathInToolchain := tool }

/-- `claude_code.hazard_scan`. -/
def scanReading (command ws : Str) : Option Reading :=
  let t := strip command
  let k := killEvidence t
  let n := networkEvidence t
  let o := outsideEvidence ws t
  let tr := traversalEvidence t
  let tc := toolchainEvidence t
  if k || n || o || tr || tc then some (scanOf k n o tr tc) else none

def isUnknownCall : J → Bool
  | .obj (("tool", .str t) :: _) => t == "unknown"
  | _ => false

/-- The Bash command of a hook input, when it has one. -/
def bashCommand? : J → Option Str
  | .obj ms =>
    match get? ms "tool_name", get? ms "tool_input" with
    | some (.str "Bash"), some (.obj ti) =>
      match get? ti "command" with
      | some (.str c) => some c.toList
      | _ => none
    | _, _ => none
  | _ => none

/-- `claude_code.hook_reading`: the mapped call's reading, or the scan's when a Bash command reads unknown and
the scan finds evidence. -/
def hookReading (d : HookDisk) (disk : Str → Disk) (hook : J) (projectDir : Option Str) (procCwd : Str) : Reading :=
  let (call, ws) := hookCall d hook projectDir procCwd
  let base := classify disk [] call
  if isUnknownCall call then
    match bashCommand? hook with
    | some c => (scanReading c ws).getD base
    | none => base
  else base

/-! ## The space of scan readings, for the per policy check -/

def bools : List Bool := [false, true]

/-- Every reading the scan can give: one per combination of evidence with some evidence. -/
def scanSpace : List Reading :=
  bools.flatMap fun k => bools.flatMap fun n => bools.flatMap fun o => bools.flatMap fun tr => bools.filterMap fun tc =>
    if k || n || o || tr || tc then some (scanOf k n o tr tc) else none

/-- A verdict that refuses: a route to a `refuse_` target, or a core refusal. -/
def isRefusal : Core.Verdict → Bool
  | .route t => "refuse_".isPrefixOf t
  | .refuse _ => true

/-- Every reading the scan can give is refused by the policy. -/
def scanSafe (p : Core.Checked) : Bool := scanSpace.all (fun r => isRefusal (Core.decideReading p (.ok r.json)))

end Classifier
