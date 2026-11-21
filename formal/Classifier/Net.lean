-- SPDX-License-Identifier: Apache-2.0
-- Copyright 2026 Crystal Warden Supply Chain Labs LLC
import Classifier.Control
/-!
# The network: what a `connect` reads as, and the policies that refuse the rest

The sandboxed agent reaches the network only through a proxy that asks the policy about each connection. The
classifier reads that request, a `connect` call with a `host` and a `port`, into `net_dest`
(docs/design/agent-sandbox-plan.md, section 3). The host is read as text, by `Classify.hostOk` and
`Classify.netDestOf`, and held to the Python by `formal/diff/classifier_diff.py`:

* `model_api`: a host of the constant `MODEL_API` table, on port 443.
* `allowed_host`: a host the owner listed (carried in `remotes` as `HOST_PREFIX ++ host`), on port 443.
* `unknown`: a host the classifier cannot read (any upper case letter, a trailing dot, userinfo, a port or a
  bracket in it, an address in any form but a dotted quad of decimal octets, a name over 253 characters) or a port
  outside 1 to 65535.
* `other`: every other readable host and port.

What is proved, in three claims kept apart:

* `netDestOf_model_api` and `netDestOf_allowed`: a `connect` reads as `model_api` or `allowed_host` only for a host
  of the table or the owner's list, on port 443.
* `netSafe p`: under the policy `p`, every reading that is a `connect` the classifier would not call the model's API
  or an allowed host (`net_dest` is `other`, `unknown` or `none`), or any reading with `net_dest` `other` or
  `unknown`, is refused, computed over the whole space of readings by the oracle's `--policy` mode
  (`net_refused`). All three shipped agent policies are `netSafe`, and the harness requires it.
* `connect_other_refused`: so a `connect` to a host that is neither in `MODEL_API` nor on the owner's list is refused
  under every `netSafe` policy, whatever the host and the port, and so is one whose host or port the classifier
  cannot read (`connect_unreadable_refused`).

What is not proved: that the proxy decides every connection it opens through this reading, and that the sandbox
leaves no other route. Those are the sandbox's and the proxy's tests.
-/

namespace Classifier

open Core (J)

/-- A reading the network rules must refuse: a destination of class `other` or `unknown`, or a `connect` that
names none. -/
def netBad (r : Reading) : Bool :=
  r.netDest == .other || r.netDest == .unknown || (r.tool == .connect && r.netDest == .none)

/-- Under `p`, every reading that `netBad` holds of is refused. -/
def netSafe (p : Core.Checked) : Bool :=
  allTools.all fun t => allScopes.all fun s => allCmds.all fun c => allGitOps.all fun g =>
  allRemotes.all fun rc => allNetDests.all fun nd => allProcClasses.all fun pc => allZones.all fun zr =>
  bools.all fun k => bools.all fun tc => bools.all fun ctl => bools.all fun gl => bools.all fun tr =>
  bools.all fun sy =>
    let r : Reading :=
      { tool := t, pathScope := s, pathInToolchain := tc, pathControl := ctl, pathGlob := gl, pathTraversal := tr,
        pathSymlink := sy, commandClass := c, killByPattern := k, gitOp := g, remoteClass := rc, netDest := nd,
        procClass := pc, zoneReach := zr }
    !netBad r || isRefusal (Core.decideReading p (.ok r.json))

/-- **Under a `netSafe` policy, a reading that `netBad` holds of is refused.** -/
theorem net_refused {p : Core.Checked} (hp : netSafe p = true) {r : Reading} (hb : netBad r = true) :
    isRefusal (Core.decideReading p (.ok r.json)) = true := by
  simp only [netSafe, List.all_eq_true] at hp
  have := hp r.tool (tool_mem _) r.pathScope (scope_mem _) r.commandClass (cmd_mem _) r.gitOp (gitop_mem _)
    r.remoteClass (remote_mem _) r.netDest (netdest_mem _) r.procClass (procclass_mem _) r.zoneReach (zone_mem _) r.killByPattern (bool_mem _)
    r.pathInToolchain (bool_mem _) r.pathControl (bool_mem _) r.pathGlob (bool_mem _) r.pathTraversal (bool_mem _)
    r.pathSymlink (bool_mem _)
  cases r
  simp_all

/-! ## What a connect reads as -/

/-- The call the classifier reads a connection from: `{"tool": "connect", "args": {"host": HOST, "port": PORT}}`. -/
def connectCall (host : String) (port : Int) : J :=
  .obj [("tool", .str "connect"), ("args", .obj [("host", .str host), ("port", .int port)])]

/-- A connect call reads as a `connect` with the class of its host and port, and names no path. -/
theorem plan_connect (remotes : List Str) (host : String) (port : Int) :
    plan remotes (connectCall host port) =
      ({ tool := .connect, netDest := netDestOf remotes host.toList port }, []) := by
  simp [plan, connectCall, get?, Core.field?, toolOf, schemaOk, schema, has, VKind.ok]

theorem classify_connect (disk : Str → Disk) (remotes : List Str) (host : String) (port : Int) :
    classifyD disk remotes (connectCall host port) =
      { tool := .connect, netDest := netDestOf remotes host.toList port } := by
  have hp := plan_connect remotes host port
  have hd : destroyPaths remotes (connectCall host port) = [] := by
    simp only [destroyPaths, hp]
    simp only [connectCall]
    split <;> rfl
  simp [classifyD, classify, hp, hd, mergePaths]

/-! ## The classes -/

theorem netDestOf_model_api {remotes : List Str} {host : Str} {port : Int}
    (h : netDestOf remotes host port = .model_api) : host ∈ MODEL_API ∧ port = 443 := by
  unfold netDestOf at h
  split at h
  · cases h
  · split at h
    · simp_all [MODEL_API_PORT]
    · split at h <;> cases h

theorem netDestOf_allowed {remotes : List Str} {host : Str} {port : Int}
    (h : netDestOf remotes host port = .allowed_host) : (HOST_PREFIX ++ host) ∈ remotes ∧ port = 443 := by
  unfold netDestOf at h
  split at h
  · cases h
  · split at h
    · cases h
    · split at h
      · simp_all [MODEL_API_PORT]
      · cases h

theorem netDestOf_ne_none (remotes : List Str) (host : Str) (port : Int) : netDestOf remotes host port ≠ .none := by
  unfold netDestOf
  split
  · intro h; cases h
  · split
    · intro h; cases h
    · split <;> intro h <;> cases h

/-- **A host that is neither of the model's API nor on the owner's list reads `other` or `unknown`.** -/
theorem netDestOf_other {remotes : List Str} {host : Str} {port : Int} (hm : host ∉ MODEL_API)
    (ha : (HOST_PREFIX ++ host) ∉ remotes) : netDestOf remotes host port = .other ∨ netDestOf remotes host port = .unknown := by
  have h1 : netDestOf remotes host port ≠ .model_api := fun h => hm (netDestOf_model_api h).1
  have h2 : netDestOf remotes host port ≠ .allowed_host := fun h => ha (netDestOf_allowed h).1
  have h3 := netDestOf_ne_none remotes host port
  generalize netDestOf remotes host port = d at h1 h2 h3 ⊢
  cases d <;> simp_all

/-- A host the classifier cannot read, or a port outside 1 to 65535, reads `unknown`. -/
theorem netDestOf_unreadable {remotes : List Str} {host : Str} {port : Int}
    (h : hostOk host = false ∨ port < 1 ∨ 65535 < port) : netDestOf remotes host port = .unknown := by
  unfold netDestOf
  rcases h with h | h | h <;> simp [h] <;> omega

/-! ## The refusals -/

theorem connect_bad {remotes : List Str} {host : Str} {port : Int} (h : netDestOf remotes host port = .other ∨
    netDestOf remotes host port = .unknown) :
    netBad { tool := .connect, netDest := netDestOf remotes host port } = true := by
  rcases h with h | h <;> simp [netBad, h]

/-- **A `connect` to a host that is neither in `MODEL_API` nor on the owner's list is refused under every `netSafe`
policy**, whatever the host and the port. -/
theorem connect_other_refused {pol : Core.Checked} (hs : netSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (host : String) (port : Int) (hm : host.toList ∉ MODEL_API)
    (ha : (HOST_PREFIX ++ host.toList) ∉ remotes) :
    isRefusal (Core.decideReading pol (.ok (classifyD disk remotes (connectCall host port)).json)) = true := by
  rw [classify_connect]
  exact net_refused hs (connect_bad (netDestOf_other hm ha))

/-- A `connect` whose host the classifier cannot read, or whose port is outside 1 to 65535, is refused under every
`netSafe` policy. -/
theorem connect_unreadable_refused {pol : Core.Checked} (hs : netSafe pol = true) (disk : Str → Disk)
    (remotes : List Str) (host : String) (port : Int) (h : hostOk host.toList = false ∨ port < 1 ∨ 65535 < port) :
    isRefusal (Core.decideReading pol (.ok (classifyD disk remotes (connectCall host port)).json)) = true := by
  rw [classify_connect]
  exact net_refused hs (connect_bad (Or.inr (netDestOf_unreadable h)))

end Classifier
