-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Core.Eval
/-!
# The classifier's syntactic reading: words, sets and the reading

The governed agent's classifier (`prismpath/agent/classifier.py`) reads one raw tool call into the typed
fields the policy routes on (docs/design/spec-verified-classifier.md). This file holds what every other file
of the model shares: strings as lists of characters (`Str`), the few operations on them the Python uses,
each defined as the Python defines it (`str.split("/")`, `str.split()`, `posixpath.basename`,
`posixpath.dirname`, `str.partition("=")`, the `_URL` search), the program and subcommand sets, and the
reading itself.

The model reads a call as JSON (`Core.J`, the core's own document type) whose strings are Unicode scalar
values. A string holding a lone surrogate is outside that domain; the Python reads such a call unknown
(`classifier.scalar`) and the oracle is told so by its transport.

Everything here is defined by structural recursion and computes; nothing uses `Classical`.
-/

namespace Classifier

open Core (J)

/-- A string as the model reads it: its characters. -/
abbrev Str := List Char

/-- A literal. -/
def lit (s : String) : Str := s.toList

/-! ## Characters -/

def isAsciiDigit (c : Char) : Bool := '0' ≤ c && c ≤ '9'
def isAsciiUpper (c : Char) : Bool := 'A' ≤ c && c ≤ 'Z'
def isAsciiLower (c : Char) : Bool := 'a' ≤ c && c ≤ 'z'
def isAsciiLetter (c : Char) : Bool := isAsciiUpper c || isAsciiLower c
/-- A word character of an ASCII regular expression (`\w` under `re.ASCII`). -/
def isAsciiWord (c : Char) : Bool := isAsciiLetter c || isAsciiDigit c || c == '_'

/-- Python's `str.isspace`: the separators of `str.split()` with no argument. -/
def isPyWs (c : Char) : Bool := Core.isPyWs c

/-! ## Operations on strings, as the Python defines them -/

/-- `s.startswith(p)`. -/
def startsWith (s p : Str) : Bool := p.isPrefixOf s

/-- `p in s` for a string `p`. -/
def hasInfix (p : Str) : Str → Bool
  | [] => p.isEmpty
  | c :: cs => p.isPrefixOf (c :: cs) || hasInfix p cs

/-- `s.split(sep)` for a one character separator, generalised to a set of separator characters
(`re.split` with a character class): every separator ends a piece, empty pieces included. -/
def splitBy (sep : Char → Bool) : Str → List Str
  | [] => [[]]
  | c :: cs =>
    if sep c then [] :: splitBy sep cs
    else match splitBy sep cs with
      | w :: ws => (c :: w) :: ws
      | [] => [[c]]

/-- `s.split("/")`. -/
def splitSlash (s : Str) : List Str := splitBy (· == '/') s

/-- `s.split()`: the words between runs of Python whitespace. -/
def pyWords (s : Str) : List Str := (splitBy isPyWs s).filter (fun w => !w.isEmpty)

/-- `posixpath.basename`: what follows the last `/`. -/
def basename (s : Str) : Str := (splitSlash s).getLastD []

/-- `s.rstrip("/")`. -/
def rstripSlash (s : Str) : Str := (s.reverse.dropWhile (· == '/')).reverse

/-- `posixpath.dirname`: up to the last `/`, trailing slashes removed unless it is all slashes. -/
def dirname (s : Str) : Str :=
  let head := s.take (s.length - (basename s).length)
  if !head.isEmpty && !head.all (· == '/') then rstripSlash head else head

/-- `s.partition("=")`: before the first `=`, whether there was one, after it. -/
def partitionEq : Str → Str × Bool × Str
  | [] => ([], false, [])
  | c :: cs =>
    if c == '=' then ([], true, cs)
    else let (h, e, v) := partitionEq cs; (c :: h, e, v)

/-- A character of a URL scheme after its first letter (`[A-Za-z0-9+.-]`). -/
def isSchemeChar (c : Char) : Bool := isAsciiLetter c || isAsciiDigit c || c == '+' || c == '.' || c == '-'

/-- `_URL.search(s)` for `[A-Za-z][A-Za-z0-9+.-]*://`. The scheme class does not hold `:`, so the starred
class consumes exactly the longest run of scheme characters and no backtracking is needed. -/
def hasURL : Str → Bool
  | [] => false
  | c :: cs => (isAsciiLetter c && (lit "://").isPrefixOf (cs.dropWhile isSchemeChar)) || hasURL cs

/-- `os.path.join(a, b)` for a `b` that does not start with `/`. -/
def join (a b : Str) : Str :=
  match a.getLast? with
  | none => b
  | some '/' => a ++ b
  | some _ => a ++ ['/'] ++ b

/-! ## The sets of `classifier.py`, word for word -/

def wordsOf (ws : List String) : List Str := ws.map lit

def READ_ONLY : List Str := wordsOf ["ls", "cat", "head", "tail", "wc", "grep", "egrep", "fgrep", "echo", "pwd",
  "true", "false", "sort", "uniq", "diff", "cmp", "stat", "file", "date", "basename", "dirname", "realpath",
  "readlink", "tree", "du", "md5sum", "sha1sum", "sha256sum", "cut", "printf", "which", "whoami", "uname", "id",
  "find", "sed", "nl", "od", "xxd", "column", "comm", "join", "paste", "rev", "seq", "tac", "test", "expr",
  "pgrep", "ps"]
def MUTATING : List Str := wordsOf ["rm", "rmdir", "mv", "cp", "ln", "chmod", "chown", "chgrp", "touch", "mkdir",
  "dd", "truncate", "shred", "tee", "install", "unlink", "tar", "unzip", "zip", "gzip", "gunzip", "patch", "kill",
  "pkill", "killall", "python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh", "dash", "make", "cargo",
  "rustc", "gcc", "cc", "npm", "npx", "pytest", "xargs", "env", "nohup", "timeout", "nice", "awk", "gawk", "mawk",
  "vim", "vi", "nano", "ed", "crontab", "systemctl"]
def NETWORK : List Str := wordsOf ["curl", "wget", "ssh", "scp", "sftp", "nc", "ncat", "netcat", "telnet", "ftp",
  "ping", "ping6", "dig", "nslookup", "host", "traceroute", "tracepath", "socat", "apt", "apt-get", "brew",
  "aria2c", "http", "https", "lynx", "w3m", "links", "rsync", "torsocks"]
def PRIVILEGE : List Str := wordsOf ["sudo", "su", "doas", "pkexec", "chroot", "nsenter", "unshare", "setpriv",
  "bwrap"]
/-- `INSTALLERS`: a program and the first arguments that make it fetch. -/
def INSTALLERS : List (Str × List Str) :=
  [(lit "pip", wordsOf ["install", "download", "wheel"]), (lit "pip3", wordsOf ["install", "download", "wheel"]),
   (lit "npm", wordsOf ["install", "i", "add", "ci", "update"]), (lit "yarn", wordsOf ["add", "install"]),
   (lit "pnpm", wordsOf ["add", "install", "i"]),
   (lit "cargo", wordsOf ["install", "fetch", "update", "search", "publish"]), (lit "gem", wordsOf ["install"]),
   (lit "go", wordsOf ["get", "install"])]
def FIND_EFFECTS : List Str := wordsOf ["-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprint0",
  "-fprintf", "-fls"]
def WRAPPERS : List Str := wordsOf ["sh", "bash", "zsh", "dash", "env", "timeout", "nohup", "nice", "xargs",
  "python", "python3", "perl", "ruby", "node", "sudo", "doas", "su", "watch", "setsid", "stdbuf", "chroot"]
def SYSTEM_DIRS : List Str := wordsOf ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
/-- `_SHELL_SEPARATORS`: `[;&|()`\n]`. -/
def isShellSeparator (c : Char) : Bool :=
  c == ';' || c == '&' || c == '|' || c == '(' || c == ')' || c == '`' || c == '\n'
/-- `GLOB_CHARS`. -/
def isGlobChar (c : Char) : Bool := c == '*' || c == '?' || c == '[' || c == ']' || c == '{' || c == '}'

def GIT_LOCAL_READ : List Str := wordsOf ["status", "log", "diff", "show", "rev-parse", "ls-files", "blame",
  "shortlog", "describe", "grep", "cat-file", "ls-tree"]
def GIT_LOCAL_WRITE : List Str := wordsOf ["add", "commit", "checkout", "switch", "stash", "tag", "merge", "branch",
  "mv", "init"]
def GIT_MUTATING : List Str := wordsOf ["rm", "clean", "restore", "filter-branch", "filter-repo", "gc", "prune",
  "reflog", "update-ref", "rebase", "cherry-pick", "revert", "am", "apply"]
def GIT_NETWORK : List Str := wordsOf ["fetch", "pull", "clone", "ls-remote", "submodule", "send-email",
  "request-pull", "archive"]
def GIT_PATH_ARGS : List Str := wordsOf ["add", "rm", "mv", "restore", "blame", "ls-files"]
def GIT_TAG_LIST_FLAGS : List Str := wordsOf ["-l", "--list", "-n", "-i", "--ignore-case", "--column", "--no-column"]
def GIT_BRANCH_LIST_FLAGS : List Str := wordsOf ["--list", "-a", "--all", "-r", "--remotes", "-v", "-vv",
  "--verbose", "--show-current", "-i", "--ignore-case", "--column", "--no-column", "--color", "--no-color",
  "--no-abbrev"]
def GIT_LIST_VALUE_FLAGS : List Str := wordsOf ["--contains", "--no-contains", "--merged", "--no-merged",
  "--points-at"]
def GIT_LIST_PREFIXES : List Str := wordsOf ["--sort=", "--format=", "--abbrev=", "--color=", "--column="]
def GIT_UNSAFE_OPTIONS : List Str := wordsOf ["--exec", "--upload-pack", "--receive-pack", "-c", "--config",
  "--git-dir", "--work-tree", "-C"]

def TOOLS : List Str := wordsOf ["list_dir", "read_file", "write_file", "delete_path", "run_command", "git"]
def MAX_PATH : Nat := 4096
def MAX_ARGV : Nat := 64
def MOUNT : Str := lit "/workspace"

/-! ## The reading -/

inductive Tool where
  | list_dir | read_file | write_file | delete_path | run_command | git | unknown
  deriving DecidableEq, Repr, Inhabited

inductive Scope where
  | none | workspace | outside | unknown
  deriving DecidableEq, Repr, Inhabited

inductive CmdClass where
  | none | read_only | mutating | network | git | unknown
  deriving DecidableEq, Repr, Inhabited

inductive GitOp where
  | none | local_read | local_write | mutating | push | network | unknown
  deriving DecidableEq, Repr, Inhabited

inductive Remote where
  | none | allowed | other
  deriving DecidableEq, Repr, Inhabited

/-- One reading. `classifier_version` is the constant `CLASSIFIER_VERSION` and is written by `Reading.json`. -/
structure Reading where
  tool : Tool := .unknown
  pathScope : Scope := .none
  pathInToolchain : Bool := false
  pathControl : Bool := false
  pathGlob : Bool := false
  pathTraversal : Bool := false
  pathSymlink : Bool := false
  commandClass : CmdClass := .none
  killByPattern : Bool := false
  gitOp : GitOp := .none
  remoteClass : Remote := .none
  deriving DecidableEq, Repr, Inhabited

/-- The unknown reading (`classifier.unknown_reading`): it routes to `agent:unclassifiable`. -/
def unknownReading : Reading := {}

def CLASSIFIER_VERSION : Nat := 1

def Tool.name : Tool → String
  | .list_dir => "list_dir" | .read_file => "read_file" | .write_file => "write_file"
  | .delete_path => "delete_path" | .run_command => "run_command" | .git => "git" | .unknown => "unknown"
def Scope.name : Scope → String
  | .none => "none" | .workspace => "workspace" | .outside => "outside" | .unknown => "unknown"
def CmdClass.name : CmdClass → String
  | .none => "none" | .read_only => "read_only" | .mutating => "mutating" | .network => "network"
  | .git => "git" | .unknown => "unknown"
def GitOp.name : GitOp → String
  | .none => "none" | .local_read => "local_read" | .local_write => "local_write" | .mutating => "mutating"
  | .push => "push" | .network => "network" | .unknown => "unknown"
def Remote.name : Remote → String
  | .none => "none" | .allowed => "allowed" | .other => "other"

/-- The reading as the document the core reads: every field the policy defines, in code point order of the
names (the canonical member order). -/
def Reading.members (r : Reading) : List (String × J) :=
  [("classifier_version", .int CLASSIFIER_VERSION),
   ("command_class", .str r.commandClass.name),
   ("git_op", .str r.gitOp.name),
   ("kill_by_pattern", .bool r.killByPattern),
   ("path_control", .bool r.pathControl),
   ("path_glob", .bool r.pathGlob),
   ("path_in_toolchain", .bool r.pathInToolchain),
   ("path_scope", .str r.pathScope.name),
   ("path_symlink", .bool r.pathSymlink),
   ("path_traversal", .bool r.pathTraversal),
   ("remote_class", .str r.remoteClass.name),
   ("tool", .str r.tool.name)]

def Reading.json (r : Reading) : J := .obj r.members

/-! ## JSON access, as `dict.get` reads it -/

def get? (ms : List (String × J)) (k : String) : Option J := Core.field? ms k

def has (ms : List (String × J)) (k : String) : Bool := ms.any (fun m => m.1 == k)

/-- A JSON string as the model's string. -/
def strOf? : J → Option Str
  | .str s => some s.toList
  | _ => none

def jstr (s : Str) : J := .str (String.ofList s)

end Classifier
