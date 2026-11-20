-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Scan
import Classifier.Control
import Classifier.Shape
/-!
# The classifier oracle

`lake exe classifier-oracle --batch` reads one JSON document per line on standard input, a case of the
differential harness (formal/diff/classifier_diff.py), and prints one JSON line per case:

    {"id": ID, "kind": "call" | "hook" | "mcp", "nonscalar": BOOL, "input": CALL | HOOK_INPUT | PARAMS,
     "remotes": [NAME...], "project_dir": DIR | null, "proc_cwd": DIR, "server_cwd": DIR,
     "disk": [[PATH, INSIDE, TOOLCHAIN, SYMLINK, CONTROL, HOLDER]...], "inside": [[PATH, ROOT, BOOL]...],
     "same": [[PATH, ROOT, BOOL]...], "exists": [[PATH, BOOL]...]}

is answered with `{"id": ID, "call": CALL, "workspace": DIR, "reading": READING}` (`call` and `workspace` for
the mappings only), or, when a disk fact the model consults is not in the tables, with
`{"id": ID, "missing": {...}}` naming every one, so the harness can observe them and ask again. Which facts
the model consults is `diskQueries`, `hookQueries` and, for a Bash command the scan reads, `scanQueries`; `Theorems.classify_local` and
`Theorems.hookCallIn_local` prove that no other fact can change the answer, so a table that holds them
determines it. `nonscalar` says the input holds a string that is not Unicode scalar values, outside the
model's domain: it reads unknown.

`lake exe classifier-oracle --policy IMAGE` reads a policy image (canon/2) and prints whether its field
definitions are ones every reading fits (`fits`), which `Theorems.boundary_accepts_every_reading` turns
into: the system boundary of that policy accepts every reading the classifier makes, and whether no reading
the hazard scan can give is allowed and every one but a push alone is refused (`scanSafe`, printed as
`scan_refused`), which `ScanTheorems.hookReading_only_adds_refusals` turns into: under that policy the scan only
ever adds refusals. It also prints whether every change that reads `path_control` is refused (`controlSafe`, printed
as `control_refused`), which `Control.control_refused` and `Control.change_on_control_refused` turn into: under that
policy a change that names a control file of the agent is refused.

Only this file does input and output; everything it prints is computed by the model's functions.
-/

namespace Classifier

open Core (J)

def esc (s : String) : String :=
  let body := s.toList.foldl (fun acc c =>
    if c == '"' then acc ++ "\\\""
    else if c == '\\' then acc ++ "\\\\"
    else if c.toNat < 0x20 then
      let h := Nat.toDigits 16 c.toNat
      acc ++ "\\u" ++ String.ofList (List.replicate (4 - h.length) '0' ++ h)
    else acc.push c) ""
  "\"" ++ body ++ "\""

partial def writeJ : J → String
  | .null => "null"
  | .bool b => if b then "true" else "false"
  | .int n => toString n
  | .str s => esc s
  | .arr xs => "[" ++ ",".intercalate (xs.map writeJ) ++ "]"
  | .obj ms => "{" ++ ",".intercalate (ms.map (fun m => esc m.1 ++ ":" ++ writeJ m.2)) ++ "}"

def jStr : J → Option Str
  | .str s => some s.toList
  | _ => none

def jBool : J → Option Bool
  | .bool b => some b
  | _ => none

def rows (ms : List (String × J)) (k : String) : List (List J) :=
  match get? ms k with
  | some (.arr xs) => xs.filterMap (fun x => match x with | .arr ys => some ys | _ => none)
  | _ => []

def diskTable (ms : List (String × J)) : List (Str × Disk) :=
  (rows ms "disk").filterMap (fun r => match r with
    | [p, i, t, s, c, h] => do pure (← jStr p, { inside := ← jBool i, toolchain := ← jBool t, symlink := ← jBool s,
                                                   control := ← jBool c, holder := ← jBool h })
    | _ => none)

def pairTable (ms : List (String × J)) (k : String) : List ((Str × Str) × Bool) :=
  (rows ms k).filterMap (fun r => match r with
    | [p, q, b] => do pure ((← jStr p, ← jStr q), ← jBool b)
    | _ => none)

def oneTable (ms : List (String × J)) (k : String) : List (Str × Bool) :=
  (rows ms k).filterMap (fun r => match r with
    | [p, b] => do pure (← jStr p, ← jBool b)
    | _ => none)

def look {α β} [BEq α] (t : List (α × β)) (k : α) : Option β := (t.find? (fun e => e.1 == k)).map (·.2)

def diskOf (t : List (Str × Disk)) (p : Str) : Disk := (look t p).getD default

def hookDiskOf (ins same : List ((Str × Str) × Bool)) (ex : List (Str × Bool)) : HookDisk :=
  { inside := fun a b => (look ins (a, b)).getD false,
    same := fun a b => (look same (a, b)).getD false,
    exists_ := fun p => (look ex p).getD false }

def readingJson (r : Reading) : String := writeJ r.json

def missingJson (disk : List Str) (ins same : List (Str × Str)) (ex : List Str) : String :=
  let s (x : Str) := esc (String.ofList x)
  let pr (x : Str × Str) := "[" ++ s x.1 ++ "," ++ s x.2 ++ "]"
  "{\"disk\":[" ++ ",".intercalate (disk.map s) ++ "],\"inside\":[" ++ ",".intercalate (ins.map pr) ++
  "],\"same\":[" ++ ",".intercalate (same.map pr) ++ "],\"exists\":[" ++ ",".intercalate (ex.map s) ++ "]}"

def answer (line : String) : String :=
  match Core.readBytes line.toUTF8 with
  | .error e => "{\"error\":" ++ esc e.name ++ "}"
  | .ok (.obj ms) =>
    let ident := match get? ms "id" with | some (.str s) => s | _ => ""
    let head := "{\"id\":" ++ esc ident
    let kind := match get? ms "kind" with | some (.str s) => s | _ => ""
    let nonscalar := match get? ms "nonscalar" with | some (.bool b) => b | _ => false
    let input := (get? ms "input").getD .null
    let remotes := match get? ms "remotes" with
      | some (.arr xs) => xs.filterMap jStr
      | _ => []
    let dt := diskTable ms
    let disk := diskOf dt
    let missingDisk (call : J) := (diskQueriesD remotes call).filter (fun p => (look dt p).isNone)
    if kind == "call" then
      let call := if nonscalar then unknownCall else input
      match missingDisk call with
      | [] => head ++ ",\"reading\":" ++ readingJson (classifyD disk remotes call) ++ "}"
      | m => head ++ ",\"missing\":" ++ missingJson m [] [] [] ++ "}"
    else if kind == "mcp" then
      let cwd := match get? ms "server_cwd" with | some (.str s) => s.toList | _ => []
      let call := if nonscalar then unknownCall else mcpCall input cwd
      match missingDisk call with
      | [] => head ++ ",\"call\":" ++ writeJ call ++ ",\"reading\":" ++ readingJson (classifyD disk remotes call) ++ "}"
      | m => head ++ ",\"missing\":" ++ missingJson m [] [] [] ++ "}"
    else if kind == "hook" then
      let pd := match get? ms "project_dir" with | some (.str s) => some s.toList | _ => none
      let pc := match get? ms "proc_cwd" with | some (.str s) => s.toList | _ => []
      let ins := pairTable ms "inside"
      let same := pairTable ms "same"
      let ex := oneTable ms "exists"
      let hd := hookDiskOf ins same ex
      let ws := workspaceFor input pd pc
      let q := hookQueries input ws
      let mIns := q.inside.filter (fun k => (look ins k).isNone)
      let mSame := q.same.filter (fun k => (look same k).isNone)
      let mEx := q.exists_.filter (fun k => (look ex k).isNone)
      if nonscalar then
        head ++ ",\"call\":" ++ writeJ unknownCall ++ ",\"workspace\":" ++ esc (String.ofList ws) ++
          ",\"reading\":" ++ readingJson (classifyD disk [] unknownCall) ++ "}"
      else if !(mIns.isEmpty && mSame.isEmpty && mEx.isEmpty) then
        head ++ ",\"missing\":" ++ missingJson [] mIns mSame mEx ++ "}"
      else
        let (call, ws') := hookCall hd input pd pc
        let scanQ := match isUnknownCall call, bashCommand? input with
          | true, some c => (scanQueries (hookCwdOf input ws') (strip c)).filter (fun p => (look dt p).isNone)
          | _, _ => []
        match missingDisk call ++ scanQ with
        | [] => head ++ ",\"call\":" ++ writeJ call ++ ",\"workspace\":" ++ esc (String.ofList ws') ++
            ",\"reading\":" ++ readingJson (hookReading hd disk input pd pc) ++ "}"
        | m => head ++ ",\"missing\":" ++ missingJson m [] [] [] ++ "}"
    else head ++ ",\"error\":\"kind\"}"
  | .ok _ => "{\"error\":\"case\"}"

end Classifier

open Classifier in
def main (args : List String) : IO UInt32 := do
  match args with
  | ["--batch"] =>
    let stdin ← IO.getStdin
    let stdout ← IO.getStdout
    let mut fuel := 100000000
    while fuel > 0 do
      fuel := fuel - 1
      let line ← stdin.getLine
      if line.isEmpty then break
      let l := (line.trimAsciiEnd).toString
      if l.isEmpty then continue
      stdout.putStrLn (answer l)
    stdout.flush
    return 0
  | ["--policy", path] =>
    let raw ← IO.FS.readBinFile path
    -- a file may end with one line feed (SPEC.md section 8)
    let img := if raw.size > 0 && raw.get! (raw.size - 1) == 10 then raw.extract 0 (raw.size - 1) else raw
    match Core.loadPolicy (Core.readCanonical img) with
    | .ok c => IO.println ("{\"policy\":\"accepted\",\"fits\":" ++ (if fitsAll c.defs then "true" else "false") ++
        ",\"scan_refused\":" ++ (if scanSafe c then "true" else "false") ++
        ",\"control_refused\":" ++ (if controlSafe c then "true" else "false") ++ "}")
    | .error _ => IO.println "{\"policy\":\"refused\"}"
    return 0
  | _ =>
    IO.eprintln "usage: classifier-oracle --batch < cases | classifier-oracle --policy IMAGE"
    return 2
