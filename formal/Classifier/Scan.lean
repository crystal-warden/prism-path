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
* network: an ASCII word in `NETWORK` inside a token that gives no path evidence, a URL scheme (`hasURL`), or an
  installer token followed by one of its fetch words (`installerEvidence`);
* outside: a token (`tokens`, split at Python whitespace, shell operators and `= : , { }`) that starts with `~`,
  or starts with `/` and is neither the workspace nor below it;
* traversal: a token with a `..` component; toolchain: a token with a `.toolchain` component;
* glob: a token with `* ? [ ]`; long: a token longer than `MAX_PATH` or holding a NUL (scope unknown);
* git: after a `git` token, an unsafe option or unknown subcommand (unknown), a network subcommand, a mutating
  one or `reset --hard` (mutating), or `push` (a push to a remote that is not allowed); the most severe wins.

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

def outsideToken (ws tok : Str) : Bool :=
  startsWith tok (lit "~") || (startsWith tok (lit "/") && !(tok == ws || startsWith tok (ws ++ ['/'])))
def traversalToken (tok : Str) : Bool := (splitSlash tok).contains (lit "..")
def toolchainToken (tok : Str) : Bool := (splitSlash tok).contains (lit ".toolchain")
/-- A glob character the token split leaves in a token (`{` and `}` split tokens). -/
def isScanGlobChar (c : Char) : Bool := c == '*' || c == '?' || c == '[' || c == ']'
def globToken (tok : Str) : Bool := tok.any isScanGlobChar
/-- The classifier's own syntactic path check, failed: longer than `MAX_PATH` or holding a NUL. -/
def longToken (tok : Str) : Bool := decide (tok.length > MAX_PATH) || tok.contains '\x00'
/-- A token that gives path evidence. -/
def pathToken (ws tok : Str) : Bool :=
  outsideToken ws tok || traversalToken tok || toolchainToken tok || globToken tok || longToken tok

/-- A network word counts only in a token that gives no path evidence (`~/.ssh/id_rsa` is a path, not ssh). -/
def networkWordEvidence (ws t : Str) : Bool :=
  (tokens t).any (fun tok => !pathToken ws tok && (asciiWords tok).any (fun w => NETWORK.contains w))

/-- The installers the scan reads: `classifier.INSTALLERS` and the system package managers. -/
def SCAN_INSTALLERS : List (Str × List Str) :=
  INSTALLERS ++ [(lit "apt", wordsOf ["install"]), (lit "apt-get", wordsOf ["install"]), (lit "brew", wordsOf ["install"]),
    (lit "dnf", wordsOf ["install"]), (lit "yum", wordsOf ["install"]), (lit "apk", wordsOf ["add"]),
    (lit "pipx", wordsOf ["install"]), (lit "conda", wordsOf ["install"]), (lit "port", wordsOf ["install"])]

def installerAt (t : Str) (rest : List Str) : Bool :=
  match SCAN_INSTALLERS.find? (fun p => p.1 == basename t) with
  | some (_, subs) => rest.any (fun a => subs.contains a)
  | none => false

/-- An installer token (by base name) with one of its fetch words in a later token. -/
def installerEvidence : List Str → Bool
  | [] => false
  | t :: rest => installerAt t rest || installerEvidence rest

def networkEvidence (ws t : Str) : Bool :=
  networkWordEvidence ws t || hasURL t || installerEvidence (tokens t)

def outsideEvidence (ws t : Str) : Bool := (tokens t).any (outsideToken ws)
def traversalEvidence (t : Str) : Bool := (tokens t).any traversalToken
def toolchainEvidence (t : Str) : Bool := (tokens t).any toolchainToken
def globEvidence (t : Str) : Bool := (tokens t).any globToken
def longEvidence (t : Str) : Bool := (tokens t).any longToken

/-! ## git -/

def GitOp.rank : GitOp → Nat
  | .push => 1 | .mutating => 2 | .network => 3 | .unknown => 4 | _ => 0

def maxOp (a b : GitOp) : GitOp := if b.rank > a.rank then b else a

/-- What the tokens after a `git` token say it does: unknown for an unsafe option or a subcommand the classifier
does not know, network, mutating (`reset --hard` included), push, or nothing for a local read or write. -/
def gitOpOf (rest : List Str) : GitOp :=
  if rest.any unsafeOption then .unknown
  else match rest.find? (fun a => !startsWith a (lit "-")) with
    | none => .none
    | some s =>
      if s == lit "push" then .push
      else if GIT_NETWORK.contains s then .network
      else if GIT_MUTATING.contains s then .mutating
      else if s == lit "reset" then (if rest.contains (lit "--hard") then .mutating else .none)
      else if s == lit "remote" then
        (if ((rest.dropWhile (· != s)).drop 1).all (fun a => a == lit "-v" || a == lit "--verbose") then .none
         else .unknown)
      else if GIT_LOCAL_READ.contains s || GIT_LOCAL_WRITE.contains s then .none
      else .unknown

/-- The most severe git operation of any `git` token (by base name). -/
def gitScan : List Str → GitOp
  | [] => .none
  | t :: rest => maxOp (if basename t == lit "git" then gitOpOf rest else .none) (gitScan rest)

/-! ## The reading -/

/-- The reading the scan gives for the evidence found. -/
def scanOf (kill net out trav tool glob long : Bool) (git : GitOp) : Reading :=
  { tool := .run_command, killByPattern := kill,
    commandClass := if net then .network else if out || trav || tool || glob || long then .mutating else .unknown,
    pathScope := if long then .unknown else if out then .outside else .none,
    pathTraversal := trav, pathInToolchain := tool, pathGlob := glob,
    gitOp := git, remoteClass := if git == .push then .other else .none }

def fires (kill net out trav tool glob long : Bool) (git : GitOp) : Bool :=
  kill || net || out || trav || tool || glob || long || git != .none

/-- `claude_code.hazard_scan`. -/
def scanReading (command ws : Str) : Option Reading :=
  let t := strip command
  let k := killEvidence t
  let n := networkEvidence ws t
  let o := outsideEvidence ws t
  let tr := traversalEvidence t
  let tc := toolchainEvidence t
  let g := globEvidence t
  let l := longEvidence t
  let gi := gitScan (tokens t)
  if fires k n o tr tc g l gi then some (scanOf k n o tr tc g l gi) else none

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
def gitOps : List GitOp := [.none, .push, .mutating, .network, .unknown]

/-- Every reading the scan can give: one per combination of evidence with some evidence. -/
def scanSpace : List Reading :=
  bools.flatMap fun k => bools.flatMap fun n => bools.flatMap fun o => bools.flatMap fun tr => bools.flatMap fun tc =>
  bools.flatMap fun g => bools.flatMap fun l => gitOps.filterMap fun gi =>
    if fires k n o tr tc g l gi then some (scanOf k n o tr tc g l gi) else none

/-- A verdict that refuses: a route to a `refuse_` target, or a core refusal. -/
def isRefusal : Core.Verdict → Bool
  | .route t => "refuse_".isPrefixOf t
  | .refuse _ => true

def isAllow : Core.Verdict → Bool
  | .route t => t == "allow"
  | .refuse _ => false

/-- The one scan reading that is not a refusal by design: a push and nothing else, which asks as before. -/
def pushOnly (r : Reading) : Bool := r == scanOf false false false false false false false .push

/-- No scan reading is allowed by the policy, and every one but the push alone is refused. -/
def scanSafe (p : Core.Checked) : Bool :=
  scanSpace.all (fun r => let v := Core.decideReading p (.ok r.json); !isAllow v && (pushOnly r || isRefusal v))

end Classifier
