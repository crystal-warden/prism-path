-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Classify
/-!
# The tool mappings: a Claude Code hook input, and an MCP `tools/call`, read into the classifier's call

`hookCall` is `claude_code.hook_call` and `mcpCall` is `mcp_map.classifier_call`, with what they read off the
disk given as inputs (`HookDisk`): whether a directory resolves inside the workspace (`_inside`), whether it
is the workspace (`_same_dir`), whether something is at a path (`_exists`); and with the process's working
directory and `CLAUDE_PROJECT_DIR` as inputs.

**The plain word grammar.** A Bash command is read only in a grammar on which the shell and this reading
agree (`splitPlain`): words separated by spaces and tabs; a word is a run of plain characters
(`isPlain`), single quoted text and double quoted text, joined; quoted text holds plain characters,
spaces, tabs, `~ { # ^` and the other quote (`isQuoted`). Anything else (a backslash, `$`, a backtick, an
operator, `~ { # ! ^` outside quotes, a control character, any non ASCII character, a quote left open) is
outside the grammar and the command reads unknown. The Python's `split_plain` is this function; it replaced
`shlex.split` (owner decision, 2026-11-17).
-/

namespace Classifier

open Core (J)

/-! ## The plain word grammar -/

/-- `claude_code.SHELL_OPERATORS`. -/
def isShellOperator (c : Char) : Bool :=
  c == '|' || c == ';' || c == '&' || c == '$' || c == '`' || c == '<' || c == '>' || c == '(' || c == ')' ||
  c == '\n' || c == '\r'

/-- `claude_code.PLAIN`: ASCII letters and digits and `- _ . / , : = + @ % * ? [ ] }`. -/
def isPlain (c : Char) : Bool :=
  isAsciiLetter c || isAsciiDigit c || c == '-' || c == '_' || c == '.' || c == '/' || c == ',' || c == ':' ||
  c == '=' || c == '+' || c == '@' || c == '%' || c == '*' || c == '?' || c == '[' || c == ']' || c == '}'

def isBlank (c : Char) : Bool := c == ' ' || c == '\t'

/-- `claude_code.QUOTED`, and the other quote: what quoted text between `q` quotes may hold. -/
def quotedBase (c : Char) : Bool := isPlain c || isBlank c || c == '~' || c == '{' || c == '#' || c == '^'

def isQuoted (q c : Char) : Bool := quotedBase c || (q == '\'' && c == '"') || (q == '"' && c == '\'')

/-- Quoted text up to the closing `q`: the text and what follows the quote, or `none` when the quote is not
closed or the text holds a character quoted text may not. -/
def quoted (q : Char) : Str → Option (Str × Str)
  | [] => none
  | c :: cs =>
    if c == q then some ([], cs)
    else if isQuoted q c then (quoted q cs).map (fun p => (c :: p.1, p.2))
    else none

/-- The words of a command, `cur` being the word in progress (`none` between words). Fuel is the length
of the input, which every step shortens. -/
def splitPlainGo : Nat → Option Str → Str → Option (List Str)
  | _, cur, [] => some (match cur with | some w => [w] | none => [])
  | 0, _, _ :: _ => none
  | fuel + 1, cur, c :: cs =>
    if isBlank c then
      match cur with
      | some w => (splitPlainGo fuel none cs).map (w :: ·)
      | none => splitPlainGo fuel none cs
    else if isPlain c then splitPlainGo fuel (some (cur.getD [] ++ [c])) cs
    else if c == '\'' || c == '"' then
      match quoted c cs with
      | some (text, rest) => splitPlainGo fuel (some (cur.getD [] ++ text)) rest
      | none => none
    else none

/-- `claude_code.split_plain`. -/
def splitPlain (s : Str) : Option (List Str) := splitPlainGo s.length none s

/-! ## The disk facts the mapping reads -/

structure HookDisk where
  inside : Str → Str → Bool     -- `_inside(path, root)`
  same : Str → Str → Bool       -- `_same_dir(path, root)`
  exists_ : Str → Bool          -- `_exists(path)`

/-! ## Spelling paths -/

def unknownCall : J := .obj [("tool", .str "unknown"), ("args", .obj [])]

/-- `_spell`: a path under `/workspace` is spelled `/./workspace...` so the classifier does not read it as
the sandbox mount. -/
def spell (raw : Str) : Str :=
  if raw == MOUNT || startsWith raw (MOUNT ++ ['/']) then lit "/." ++ raw else raw

/-- `_absolute`. -/
def absolute (raw : Option J) (cwd : Str) : Option Str :=
  match raw with
  | some (.str s) =>
    let r := s.toList
    if r.isEmpty || startsWith r (lit "~") then none
    else if startsWith r (lit "/") then some (spell r)
    else some (spell (join cwd r))
  | _ => none

/-- `_spell_word`. -/
def spellWord (w : Str) : Str :=
  let (head, eq, value) := if startsWith w (lit "-") then partitionEq w else ([], false, w)
  if startsWith value (lit "/") then head ++ (if eq then ['='] else []) ++ spell value else w

/-- `_from_cwd`. -/
def fromCwd (d : HookDisk) (cwd w : Str) : Str :=
  let (head, eq, value) := if startsWith w (lit "-") then partitionEq w else ([], false, w)
  let pre := head ++ (if eq then ['='] else [])
  if startsWith w (lit "-") && !(eq && value.contains '/') then w
  else if startsWith value (lit "/") then pre ++ spell value
  else if value.contains '/' || startsWith value (lit ".") || d.exists_ (join cwd value) then
    pre ++ spell (join cwd value)
  else w

/-- `_bash_argv`. -/
def bashArgv (d : HookDisk) (command : Option J) (cwd ws : Str) : Option (List Str) :=
  match command with
  | some (.str s) =>
    let c := s.toList
    if c.any isShellOperator then none
    else match splitPlain c with
      | none | some [] => none
      | some (w0 :: rest) =>
        if !d.inside cwd ws then none
        else if rest.any (fun w => startsWith w (lit "~") || w.contains '{') then none
        else
          let here := d.same cwd ws
          some (w0 :: rest.map (fun w => if here then spellWord w else fromCwd d cwd w))
  | _ => none

/-! ## The Claude Code mapping -/

/-- `_first_path`: the value of the first of `file_path`, `notebook_path` present (`none` for JSON null). -/
def firstPath (ms : List (String × J)) : Option J :=
  match get? ms "file_path" with
  | some .null => none
  | some v => some v
  | none => match get? ms "notebook_path" with
    | some .null => none
    | some v => some v
    | none => none

def hasPathKey (ms : List (String × J)) : Bool := has ms "file_path" || has ms "notebook_path"

/-- `_file_paths`: every path a file tool names (each `none` for a JSON null), or `none` when one is missing
or not a non empty string. -/
def filePaths (ms : List (String × J)) : Option (List J) :=
  let top := (firstPath ms).toList
  let edits := match get? ms "edits" with
    | some (.arr es) => es.filterMap (fun e => match e with
        | .obj em => if hasPathKey em then some ((firstPath em).getD .null) else none
        | _ => none)
    | _ => []
  let paths := top ++ edits
  if paths.isEmpty || !paths.all (fun p => match p with | .str s => !s.isEmpty | _ => false) then none
  else some paths

def writeCall (p : Str) : J := .obj [("tool", .str "write_file"), ("args", .obj [("path", jstr p), ("content", .str "")])]
def pathCall (tool : String) (p : Str) : J := .obj [("tool", .str tool), ("args", .obj [("path", jstr p)])]

def isWriteTool (name : String) : Bool :=
  name == "Write" || name == "Edit" || name == "MultiEdit" || name == "NotebookEdit"

/-- `_list_call`. -/
def listCall (name : String) (ti : List (String × J)) (cwd : Str) : J :=
  if has ti "paths" then unknownCall
  else
    let base := match get? ti "path" with | some .null => none | b => b
    match base with
    | some b =>
      match b with
      | .str s =>
        if s.isEmpty then unknownCall
        else match absolute (some b) cwd with
          | none => unknownCall
          | some baseAbs => listWith baseAbs
      | _ => unknownCall
    | none => listWith (spell cwd)
where
  listWith (baseAbs : Str) : J :=
    if name == "Glob" then
      match get? ti "pattern" with
      | some (.str ps) =>
        let pat := ps.toList
        if pat.isEmpty || startsWith pat (lit "~") then unknownCall
        else pathCall "list_dir" (if startsWith pat (lit "/") then spell pat else rstripSlash baseAbs ++ ['/'] ++ pat)
      | _ => unknownCall
    else pathCall "list_dir" baseAbs

/-- `workspace_for`: `CLAUDE_PROJECT_DIR` when set and not empty, else the input's `cwd`, else the process's. -/
def workspaceFor (hook : J) (projectDir : Option Str) (procCwd : Str) : Str :=
  match projectDir with
  | some d => if d.isEmpty then fallback else d
  | none => fallback
where
  fallback : Str :=
    let root := match hook with
      | .obj ms => match get? ms "cwd" with | some (.str s) => s.toList | _ => []
      | _ => []
    if root.isEmpty then procCwd else root

/-- The directory a hook input's relative paths are read against: its `cwd` when a non empty string, else the
workspace. -/
def hookCwd (ms : List (String × J)) (ws : Str) : Str :=
  match get? ms "cwd" with
  | some (.str s) => if s.isEmpty then ws else s.toList
  | _ => ws

def runCall (argv : List Str) : J := .obj [("tool", .str "run_command"), ("args", .obj [("argv", .arr (argv.map jstr))])]

/-- The call of one named Claude Code tool with its input object, from `cwd` against the workspace `ws`. -/
def hookTool (d : HookDisk) (name : String) (ti : List (String × J)) (cwd ws : Str) : J :=
  if name == "Read" then
    match absolute (get? ti "file_path") cwd with
    | some p => pathCall "read_file" p
    | none => unknownCall
  else if isWriteTool name then
    match filePaths ti with
    | none => unknownCall
    | some paths =>
      match paths.map (fun p => absolute (some p) cwd) with
      | some p :: rest => if rest.all (· == some p) then writeCall p else unknownCall
      | _ => unknownCall
  else if name == "Glob" || name == "Grep" || name == "LS" then listCall name ti cwd
  else if name == "Bash" then
    match bashArgv d (get? ti "command") cwd ws with
    | some argv => runCall argv
    | none => unknownCall
  else unknownCall

/-- `_call`: the classifier call of one hook input against the workspace `ws`. -/
def hookCallIn (d : HookDisk) (hook : J) (ws : Str) : J :=
  match hook with
  | .obj ms =>
    match get? ms "tool_name", get? ms "tool_input" with
    | some (.str name), some (.obj ti) => hookTool d name ti (hookCwd ms ws) ws
    | _, _ => unknownCall
  | _ => unknownCall

/-- `claude_code.hook_call`: the call and the workspace it is classified against. -/
def hookCall (d : HookDisk) (hook : J) (projectDir : Option Str) (procCwd : Str) : J × Str :=
  let ws := workspaceFor hook projectDir procCwd
  (hookCallIn d hook ws, ws)

/-- The reading of a hook input (`claude_code.evaluate` up to the decision): the mapped call classified
against the workspace's disk, with no allowed remote (`Config.for_workspace`). -/
def hookReading (d : HookDisk) (disk : Str → Disk) (hook : J) (projectDir : Option Str) (procCwd : Str) : Reading :=
  classify disk [] (hookCall d hook projectDir procCwd).1

/-! ## The MCP mapping -/

/-- `mcp_map._FS`: a filesystem tool's classifier tool, required keys and optional keys. -/
def fsTool : String → Option (String × List String × List String)
  | "read_text_file" => some ("read_file", ["path"], ["head", "tail"])
  | "read_media_file" => some ("read_file", ["path"], [])
  | "get_file_info" => some ("read_file", ["path"], [])
  | "list_directory" => some ("list_dir", ["path"], [])
  | "list_directory_with_sizes" => some ("list_dir", ["path"], ["sortBy"])
  | "directory_tree" => some ("list_dir", ["path"], ["excludePatterns"])
  | "search_files" => some ("list_dir", ["path", "pattern"], ["excludePatterns"])
  | "edit_file" => some ("write_file", ["path", "edits"], ["dryRun"])
  | "create_directory" => some ("write_file", ["path"], [])
  | "list_allowed_directories" => some ("list_dir", [], [])
  | _ => none

/-- `mcp_map.host_path`. -/
def mcpHostPath (raw : Option J) (serverCwd : Str) : Option Str :=
  match raw with
  | some (.str s) =>
    let r := s.toList
    if r.isEmpty || startsWith r (lit "~") then none
    else if startsWith r (lit "/") then some (spell r)
    else some (spell (join serverCwd r))
  | _ => none

/-- `mcp_map.classifier_call`. -/
def mcpCall (params : J) (serverCwd : Str) : J :=
  match params with
  | .obj ps =>
    let arguments := (get? ps "arguments").getD (.obj [])
    match get? ps "name", arguments with
    | some (.str name), .obj am =>
      if TOOLS.contains name.toList then .obj [("tool", .str name), ("args", .obj am)]
      else match fsTool name with
        | none => unknownCall
        | some (tool, req, opt) =>
          if !req.all (fun k => has am k) || !am.all (fun m => (req ++ opt).contains m.1) then unknownCall
          else if req.isEmpty then .obj [("tool", .str tool), ("args", .obj [])]
          else match mcpHostPath (get? am "path") serverCwd with
            | none => unknownCall
            | some path =>
              let path' : Option Str :=
                if name == "search_files" then
                  match get? am "pattern" with
                  | some (.str ps) =>
                    let pat := ps.toList
                    if pat.isEmpty || startsWith pat (lit "~") || startsWith pat (lit "/") then none
                    else some (rstripSlash path ++ ['/'] ++ pat)
                  | _ => none
                else some path
              match path' with
              | none => unknownCall
              | some p => if tool == "write_file" then writeCall p else pathCall tool p
    | _, _ => unknownCall
  | _ => unknownCall

end Classifier

namespace Classifier

open Core (J)

/-! ## The disk facts the Claude Code mapping consults -/

structure HookQ where
  inside : List (Str × Str) := []
  same : List (Str × Str) := []
  exists_ : List Str := []

/-- The value part of a word, as `_from_cwd` reads it. -/
def wordValue (w : Str) : Str := (if startsWith w (lit "-") then partitionEq w else ([], false, w)).2.2

/-- The disk facts `hookCallIn` may consult for a hook input against the workspace `ws`: for a Bash command in
the grammar, whether its `cwd` is inside and is the workspace, and whether each later word names something
there. It is an over-approximation (`_exists` is asked only for some words); `hookCallIn_local` proves that
no fact outside it changes the call. -/
def bashQueries (ti : List (String × J)) (cwd ws : Str) : HookQ :=
  match get? ti "command" with
  | some (.str s) =>
    match splitPlain s.toList with
    | some (_ :: rest) => { inside := [(cwd, ws)], same := [(cwd, ws)],
                            exists_ := rest.map (fun w => join cwd (wordValue w)) }
    | _ => {}
  | _ => {}

def hookQueries (hook : J) (ws : Str) : HookQ :=
  match hook with
  | .obj ms =>
    match get? ms "tool_name", get? ms "tool_input" with
    | some (.str name), some (.obj ti) => if name == "Bash" then bashQueries ti (hookCwd ms ws) ws else {}
    | _, _ => {}
  | _ => {}

end Classifier
