-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Basic
/-!
# The classifier's syntactic reading of one call

`classify disk remotes call` is `classifier.classify(call, config)` with the disk observations given as an
input: `disk raw` is what `classifier.disk_facts(raw, config)` observes of a path that passed the syntactic
checks (inside the workspace, into a toolchain directory, through a symbolic link), and `remotes` is
`config.allowed_remotes`. Nothing here reads a disk: what the model proves, it proves for every value those
observations can take.

The structure follows the Python function by function: `pathFacts` is `path_facts`, `pathLike` is
`_path_like_args`, `killArgsByPid` and `killByPattern` are the kill readers, `commandClass` is
`command_class`, `gitListing` and `gitFacts` are the git readers, `schemaOk` is `_schema_ok`. One change of
shape keeps the theorems short: `plan` computes the reading without its path facts and the list of paths
whose facts it merges, and `classify` merges them (`classify_eq`), so the disk is consulted at exactly the
paths `plan` names (`Theorems.classify_local`).
-/

namespace Classifier

open Core (J)

/-! ## Paths -/

/-- The observations of one path on the disk (`classifier.DiskFacts`). -/
structure Disk where
  inside : Bool
  toolchain : Bool
  symlink : Bool
  control : Bool
  holder : Bool
  deriving DecidableEq, Repr, Inhabited

/-- The facts of one named path (`classifier.PathFacts`). -/
structure PathFacts where
  scope : Scope
  toolchain : Bool := false
  glob : Bool := false
  traversal : Bool := false
  symlink : Bool := false
  control : Bool := false
  deriving DecidableEq, Repr, Inhabited

/-- The syntactic check of a named path: a non empty string with no NUL, at most `MAX_PATH` characters. -/
def pathOk (raw : Str) : Bool := !raw.isEmpty && !raw.contains '\x00' && raw.length ≤ MAX_PATH

/-- A glob: a pattern character anywhere, or a leading `~`. -/
def isGlob (raw : Str) : Bool := raw.any isGlobChar || startsWith raw (lit "~")

/-- A `..` component. -/
def isTraversal (raw : Str) : Bool := (splitSlash raw).contains (lit "..")

def pathFacts (disk : Str → Disk) (raw : Str) : PathFacts :=
  if pathOk raw then
    let d := disk raw
    { scope := if d.inside then .workspace else .outside, toolchain := d.toolchain, glob := isGlob raw,
      traversal := isTraversal raw, symlink := d.symlink, control := d.control }
  else { scope := .unknown }

def Scope.rank : Scope → Nat
  | .none => 0 | .workspace => 1 | .outside => 2 | .unknown => 3

def mergeOne (r : Reading) (f : PathFacts) : Reading :=
  { r with pathScope := if f.scope.rank > r.pathScope.rank then f.scope else r.pathScope,
           pathInToolchain := r.pathInToolchain || f.toolchain,
           pathGlob := r.pathGlob || f.glob,
           pathTraversal := r.pathTraversal || f.traversal,
           pathSymlink := r.pathSymlink || f.symlink,
           pathControl := r.pathControl || f.control }

/-- `_merge_paths`. -/
def mergePaths (r : Reading) (fs : List PathFacts) : Reading := fs.foldl mergeOne r

/-- `_path_like_args`: every non option word, every word after `--`, and the value of an `--option=value`
that holds a slash. -/
def pathLike : Bool → List Str → List Str
  | _, [] => []
  | true, a :: r => a :: pathLike true r
  | false, a :: r =>
    if a == lit "--" then pathLike true r
    else if startsWith a (lit "-") then
      let (_, eq, v) := partitionEq a
      if eq && v.contains '/' then v :: pathLike false r else pathLike false r
    else a :: pathLike false r

/-! ## Kill by pattern -/

/-- `_SIGNAL.fullmatch` (ASCII): `-` then digits, or an upper case letter and upper case letters or digits. -/
def isSignal : Str → Bool
  | '-' :: rest =>
    (!rest.isEmpty && rest.all isAsciiDigit) ||
    (match rest with
     | c :: cs => isAsciiUpper c && cs.all (fun x => isAsciiUpper x || isAsciiDigit x)
     | [] => false)
  | _ => false

/-- One positive process id: ASCII digits, not `0`. -/
def isPid (a : Str) : Bool := !a.isEmpty && a.all isAsciiDigit && a != lit "0"

/-- `_kill_args_by_pid`: `kill [-SIGNAL | -s SIGNAL] PID...` with every target one positive process id. -/
def killArgsByPid (args : List Str) : Bool :=
  let rest := match args with
    | a :: b :: r => if a == lit "-s" then r else if isSignal a then b :: r else a :: b :: r
    | [a] => if isSignal a then [] else [a]
    | [] => []
  !rest.isEmpty && rest.all isPid

/-- `w` at the front of `s` with an ASCII word boundary after it. -/
def wordAt (w s : Str) : Bool :=
  w.isPrefixOf s && (match s.drop w.length with
    | [] => true
    | d :: _ => !isAsciiWord d)

/-- `_KILL_WORD.search` (ASCII `\b(pkill|killall)\b`), scanning with whether the previous character is a word
character. -/
def killWordFrom : Bool → Str → Bool
  | _, [] => false
  | prev, c :: cs =>
    (!prev && (wordAt (lit "pkill") (c :: cs) || wordAt (lit "killall") (c :: cs))) ||
    killWordFrom (isAsciiWord c) cs

def hasKillWord (s : Str) : Bool := killWordFrom false s

/-- A `kill` word whose following words are not all process ids. -/
def innerKill : List Str → Bool
  | [] => false
  | w :: ws => (w == lit "kill" && !killArgsByPid ws) || innerKill ws

/-- A kill written in one argument of a program that runs other programs. -/
def argKills (arg : Str) : Bool :=
  hasKillWord arg || (splitBy isShellSeparator arg).any (fun cmd => innerKill (pyWords cmd))

/-- `kill_by_pattern` of a non empty argv. -/
def killByPattern : List Str → Bool
  | [] => false
  | a0 :: args =>
    let base := basename a0
    if base == lit "pkill" || base == lit "killall" then true
    else if base == lit "kill" && !killArgsByPid args then true
    else if base == lit "xargs" && args.contains (lit "kill") then true
    else if !WRAPPERS.contains base then false
    else args.any argKills

/-! ## Command class -/

/-- The program an argv names, or `none` for a program of the workspace (a path not in a system directory). -/
def program (first : Str) : Option Str :=
  if startsWith first (lit "/") && SYSTEM_DIRS.contains (dirname first) then some (basename first)
  else if first.contains '/' then none
  else some first

def installerFetches (base : Str) (args : List Str) : Bool :=
  match INSTALLERS.find? (fun p => p.1 == base) with
  | some (_, subs) => (args.take 1).any (fun a => subs.contains a)
  | none => false

def isInstaller (base : Str) : Bool := INSTALLERS.any (fun p => p.1 == base)

/-- `command_class` of a non empty argv. -/
def commandClass : List Str → CmdClass
  | [] => .unknown
  | first :: args =>
    match program first with
    | none => .mutating
    | some base =>
      if base.isEmpty || PRIVILEGE.contains base then .unknown
      else if base == lit "git" then .git
      else if NETWORK.contains base || args.any hasURL then .network
      else if installerFetches base args then .network
      else if (base == lit "python" || base == lit "python3") && args.take 2 == [lit "-m", lit "pip"] then .network
      else if base == lit "find" && args.any (fun a => FIND_EFFECTS.contains a) then .mutating
      else if base == lit "sed" && args.any (fun a => a == lit "-i" || startsWith a (lit "-i") ||
          startsWith a (lit "--in-place")) then .mutating
      else if base == lit "sort" && args.any (fun a => a == lit "-o" || startsWith a (lit "--output")) then .mutating
      else if base == lit "tree" && args.contains (lit "-o") then .mutating
      else if READ_ONLY.contains base then .read_only
      else if MUTATING.contains base || isInstaller base then .mutating
      else .unknown

/-! ## git -/

/-- `-n` and one or more ASCII digits. -/
def isNDigits : Str → Bool
  | '-' :: 'n' :: ds => !ds.isEmpty && ds.all isAsciiDigit
  | _ => false

def listLoop (isTag : Bool) (flags : List Str) (listing : Bool) : Bool → List Str → Bool
  | ev, [] => !ev
  | true, a :: r => if startsWith a (lit "-") then false else listLoop isTag flags listing false r
  | false, a :: r =>
    if GIT_LIST_VALUE_FLAGS.contains a then listLoop isTag flags listing true r
    else if flags.contains a || GIT_LIST_PREFIXES.any (startsWith a) || (isTag && isNDigits a) then
      listLoop isTag flags listing false r
    else if startsWith a (lit "-") || !listing then false
    else listLoop isTag flags listing false r

/-- `git_listing` for `tag` (`isTag`) or `branch`. -/
def gitListing (isTag : Bool) (args : List Str) : Bool :=
  let flags := if isTag then GIT_TAG_LIST_FLAGS else GIT_BRANCH_LIST_FLAGS
  let switch := if isTag then [lit "-l", lit "--list"] else [lit "--list"]
  listLoop isTag flags (args.any (fun a => switch.contains a)) false args

def unsafeOption (a : Str) : Bool := GIT_UNSAFE_OPTIONS.any (fun o => a == o || startsWith a (o ++ ['=']))

/-- `git_facts`: the operation, the remote class, and the paths whose facts the reading merges. `sub` is
`none` when the subcommand is not a string; `args` is `none` when the arguments are not a list of at most
`MAX_ARGV` strings without NUL. -/
def gitPlan (remotes : List Str) (sub : Option Str) (args : Option (List Str)) : GitOp × Remote × List Str :=
  match sub, args with
  | some s, some as =>
    if s.isEmpty || startsWith s (lit "-") then (.unknown, .none, [])
    else if as.any unsafeOption then (.unknown, .none, [])
    else if s == lit "push" then
      let remote := ((as.filter (fun a => !startsWith a (lit "-"))).head?).getD (lit "origin")
      (.push, if remotes.contains remote then .allowed else .other, [])
    else if as.any hasURL || GIT_NETWORK.contains s then (.network, .none, [])
    else if s == lit "remote" then
      (if as.all (fun a => a == lit "-v" || a == lit "--verbose") then .local_read else .unknown, .none, [])
    else if s == lit "reset" then (if as.contains (lit "--hard") then .mutating else .local_write, .none, [])
    else
      let paths := if GIT_PATH_ARGS.contains s then pathLike false as else []
      if GIT_LOCAL_READ.contains s then (.local_read, .none, paths)
      else if (s == lit "tag" || s == lit "branch") && gitListing (s == lit "tag") as then (.local_read, .none, paths)
      else if GIT_LOCAL_WRITE.contains s then (.local_write, .none, paths)
      else if GIT_MUTATING.contains s then (.mutating, .none, paths)
      else (.unknown, .none, [])
  | _, _ => (.unknown, .none, [])

/-! ## One call -/

/-- A value's kind as the schema names it. -/
inductive VKind where
  | str | list
  deriving DecidableEq

def VKind.ok : VKind → J → Bool
  | .str, .str _ => true
  | .list, .arr _ => true
  | _, _ => false

/-- `_SCHEMA`: the required and optional keys of each tool, with the kind of each value. -/
def schema : Tool → List (String × VKind) × List (String × VKind)
  | .list_dir => ([], [("path", .str)])
  | .read_file => ([("path", .str)], [])
  | .write_file => ([("path", .str), ("content", .str)], [])
  | .delete_path => ([("path", .str)], [])
  | .run_command => ([("argv", .list)], [])
  | .git => ([("subcommand", .str)], [("args", .list)])
  | .unknown => ([], [])

/-- `_schema_ok`. -/
def schemaOk (t : Tool) : J → Bool
  | .obj ms =>
    let (req, opt) := schema t
    req.all (fun k => has ms k.1) && ms.all (fun m => (req ++ opt).any (fun k => k.1 == m.1)) &&
    (req ++ opt).all (fun k => match get? ms k.1 with | some v => k.2.ok v | none => true)
  | _ => false

def toolOf (s : String) : Tool :=
  match s with
  | "list_dir" => .list_dir | "read_file" => .read_file | "write_file" => .write_file
  | "delete_path" => .delete_path | "run_command" => .run_command | "git" => .git | _ => .unknown

/-- An argv as `_classify` accepts it: a non empty list of at most `MAX_ARGV` non empty strings without NUL. -/
def argvOf? (xs : List J) : Option (List Str) :=
  if xs.isEmpty || xs.length > MAX_ARGV then none
  else xs.mapM (fun x => match x with
    | .str s => let t := s.toList; if t.isEmpty || t.contains '\x00' then none else some t
    | _ => none)

/-- git's arguments as `git_facts` accepts them: at most `MAX_ARGV` strings without NUL. -/
def gitArgsOf? (xs : List J) : Option (List Str) :=
  if xs.length > MAX_ARGV then none
  else xs.mapM (fun x => match x with
    | .str s => let t := s.toList; if t.contains '\x00' then none else some t
    | _ => none)

/-- The reading of a run_command argv before its paths are merged, and the paths. -/
def runPlan (remotes : List Str) (argv : List Str) : Reading × List Str :=
  let base : Reading := { tool := .run_command, killByPattern := killByPattern argv, commandClass := commandClass argv }
  if base.commandClass == .git then
    let (op, rc, ps) := gitPlan remotes (argv.drop 1).head? (some (argv.drop 2))
    ({ base with gitOp := op, remoteClass := rc }, ps)
  else (base, pathLike false (argv.drop 1))

/-- The reading of one call before its path facts are merged, and the paths whose facts it merges. -/
def plan (remotes : List Str) (call : J) : Reading × List Str :=
  match call with
  | .obj ms =>
    if !ms.all (fun m => m.1 == "tool" || m.1 == "args") then (unknownReading, [])
    else match get? ms "tool" with
      | some (.str name) =>
        let t := toolOf name
        let args := (get? ms "args").getD (.obj [])
        if t == .unknown || !schemaOk t args then (unknownReading, [])
        else match args with
          | .obj am =>
            match t with
            | .list_dir | .read_file | .write_file | .delete_path =>
              let raw := match get? am "path" with | some (.str p) => p.toList | _ => lit "."
              ({ tool := t }, [raw])
            | .git =>
              let sub := match get? am "subcommand" with | some (.str s) => some s.toList | _ => none
              let gargs := match get? am "args" with | some (.arr xs) => gitArgsOf? xs | _ => some []
              let (op, rc, ps) := gitPlan remotes sub gargs
              ({ tool := .git, gitOp := op, remoteClass := rc }, ps)
            | .run_command =>
              match get? am "argv" with
              | some (.arr xs) =>
                match argvOf? xs with
                | some argv => runPlan remotes argv
                | none => ({ tool := .run_command, commandClass := .unknown }, [])
              | _ => (unknownReading, [])
            | .unknown => (unknownReading, [])
          | _ => (unknownReading, [])
      | _ => (unknownReading, [])
  | _ => (unknownReading, [])

/-- `classifier.classify`: the reading of one call, given the disk's observations of the paths it names. -/
def classify (disk : Str → Disk) (remotes : List Str) (call : J) : Reading :=
  let (r, ps) := plan remotes call
  mergePaths r (ps.map (pathFacts disk))

/-- The paths at which `classify` consults the disk: the planned paths that pass the syntactic check. -/
def diskQueries (remotes : List Str) (call : J) : List Str := (plan remotes call).2.filter pathOk

/-! ## Removing or moving a directory that holds control files -/

/-- The paths of `git rm` and `git clean`: a directory that holds control files is a control target there. -/
def gitDestroy (sub : Option Str) (rest : List Str) : List Str :=
  match sub with
  | some s => if s == lit "rm" || s == lit "clean" then pathLike false rest else []
  | none => []

/-- The paths an argv names where it removes or moves them: every path of `rm` and `rmdir`, every path of `mv` but
the last, the paths of `find ... -delete`, and the paths of `git rm` and `git clean`
(`classifier.destroy_paths`). -/
def destroyArgs : List Str → List Str
  | [] => []
  | first :: args =>
    match program first with
    | none => []
    | some base =>
      if base == lit "rm" || base == lit "rmdir" then pathLike false args
      else if base == lit "mv" then (pathLike false args).dropLast
      else if base == lit "find" && args.contains (lit "-delete") then pathLike false args
      else if base == lit "git" then gitDestroy args.head? (args.drop 1)
      else []

/-- `classifier.destroy_paths` of a call. -/
def destroyPaths (remotes : List Str) (call : J) : List Str :=
  let pl := plan remotes call
  if pl.1.tool == .delete_path then pl.2
  else match call with
    | .obj ms =>
      match get? ms "args" with
      | some (.obj am) =>
        if pl.1.tool == .run_command then
          match get? am "argv" with
          | some (.arr xs) => match argvOf? xs with | some argv => destroyArgs argv | none => []
          | _ => []
        else if pl.1.tool == .git then
          match get? am "subcommand" with
          | some (.str s) =>
            match (match get? am "args" with | some (.arr xs) => gitArgsOf? xs | _ => some []) with
            | some gargs => gitDestroy (some s.toList) gargs
            | none => []
          | _ => []
        else []
      | _ => []
    | _ => []

def holderHit (disk : Str → Disk) (p : Str) : Bool := pathOk p && (disk p).holder

/-- `classifier.classify`, including the directories a removal or a move names: the reading of `classify`, with
`path_control` also set when a path in `destroyPaths` is the workspace root or holds control files. Only
`path_control` differs from `classify`. -/
def classifyD (disk : Str → Disk) (remotes : List Str) (call : J) : Reading :=
  let r := classify disk remotes call
  { r with pathControl := r.pathControl || (destroyPaths remotes call).any (holderHit disk) }

/-- The paths at which `classifyD` consults the disk. -/
def diskQueriesD (remotes : List Str) (call : J) : List Str :=
  diskQueries remotes call ++ (destroyPaths remotes call).filter pathOk

end Classifier
