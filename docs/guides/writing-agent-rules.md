# Writing agent rules

A governed agent asks before every tool call it makes. The answer comes from a signed policy image, and
you write that policy as a short list of rules in a Markdown file. You do not write JSON. This guide is
for the person who owns those rules.

## The file

The agent's own rules are in `prismpath/agent/policy/agent_rules.rules.md`. A smaller example:

```
---
name: my_rules
field.tool: category
field.path_scope: category
field.command_class: category
field.git_op: category
field.kill_by_pattern: bool
field.path_control: bool
field.net_dest: category
---
## core_decision
Rules are read from the top. The first one that holds decides.

-> refuse agent:unclassifiable: when tool == "unknown" or path_scope == "unknown" or git_op == "unknown"
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> refuse agent:control-write: when path_control
-> refuse agent:net-refused: when tool == "connect" or net_dest != "none"
-> allow: when tool == "read_file" and path_scope == "workspace"
```

It lets the agent read files in the project and nothing else. The control file and connection rules are
there because the agent needs them, as the field list below explains.

The part between the two `---` lines declares the fields. Each field is one fact the classifier reads
off a call, and each has a kind.

| kind | holds | example |
|---|---|---|
| `bool` | true or false | `field.path_glob: bool` |
| `category` | one word from a set | `field.tool: category` |
| `int` | a whole number, with bounds if you want them | `field.classifier_version: int min=1 max=1` |
| `fixed` | a decimal on a fixed grid | `field.cost: fixed scale=100 rounding=exact` |

Add `absent=allowed` when a reading may leave a field out. A rule must then test that field for
`None`, so the case of a missing value is decided on purpose.

Under `## core_decision` each line that starts with `->` is one rule. Any other line is a note for the
reader and changes nothing. A note that looks like a rule, such as `> refuse agent:network: always` or
`allow: when ...` with no arrow, compiles with a warning on its line, because the refusal you meant to
write is not in the policy.

## A rule

A rule says what happens and when.

```
-> refuse agent:network: when command_class == "network"
```

What happens is one of three things.

* `allow` runs the call, in the sandbox.
* `refuse <cause>` never runs it. The cause is a registered name such as `agent:network`.
* `escalate <cause>` holds the call for a person and does not run it.

The causes are registered in `prismpath/kernel/causes.py`, and `prismpath policy causes` lists the ones a
rule names, with their codes. They are also in the table at the end of this guide. A name that is not
registered is an error, so a typo cannot slip into a signed policy. You cannot make up a new cause in a
rules file. A registered cause that is not one a policy decides, such as `sig:missing`, compiles with a
warning, because a receipt that names it would report a check that never ran.

When is `always`, `never`, or `when` and a condition over the fields.

* a `bool` field on its own: `when kill_by_pattern`
* a comparison with a value: `==` `!=` `<` `<=` `>` `>=`, as in `when path_scope == "outside"`
* membership: `when tool in ["write_file", "delete_path"]`, and `not in`
* `and`, `or`, `not` and parentheses to combine them

Words are compared with `==` and `!=` only. A field is compared with a value, never with another field.

Order matters. The first rule that holds decides, so put the refusals first and the allows last. A call
that no rule allows is refused. Moving one line changes the policy, and the compiled image changes with
it.

## Compile, check, read back

```
prismpath policy compile agent_rules.rules.md -o agent_rules.core.json
```

This writes the policy image the agent loads, and it checks the rules the way the verified core does.
A problem is named with its line. The compiler reads the whole file first and then checks the rules,
so a mistake in how a line is written is reported before a mistake in what it means. In the small example
above, a misspelled cause on line 15 gives

```
prismpath policy compile: my_rules.rules.md:15: agent:kill-by-patern is not a registered cause name; did you mean agent:kill-by-pattern?
```

With that fixed, `tool == 1` on line 18 gives

```
prismpath policy compile: my_rules.rules.md:18: the rule compares a field with a value of another kind (policy:kind-mismatch: field tool)
```

Nothing is written until the file compiles.

The core accepts any rules that are well formed. The agent needs more, so check a policy for it with
`--target agent`:

```
prismpath policy compile --target agent my_rules.rules.md -o my_rules.core.json
```

This also refuses, each on its line, a value outside a field's list (`tool == "readfile"`), a field the
classifier does not read (`field.path_controll`), a missing required field, a policy that lets a change to
a control file or a connection through, and one the sandbox cannot be built from. It takes a few seconds,
because it asks the policy about every call the classifier can read. Without `--target` the agent finds
these only when it loads the policy or refuses a call. The compiler also warns about a rule that no call can
reach because an `always` rule sits above it.

To read an existing image as rules:

```
prismpath policy render agent_rules.core.json
```

Compiling what `render` prints gives the same image, byte for byte. The rules files shipped with the
agent compile to the shipped images byte for byte, and a test holds them to that.

## The classifier

The rules only see the fields. Something has to read a raw tool call and fill them in, and that is the
classifier. It is trusted code outside the verified core: if it says a call only reads when it deletes,
a correct core will allow the delete. An engineer writes it. To give them a starting point:

```
prismpath policy skeleton my_rules.rules.md -o my_classifier.py
```

This writes `my_classifier.py` and `test_my_classifier.py`. Every field starts at its most cautious
value: `unknown` for a category, false for a bool, the lowest allowed number, and missing where a field
may be missing. The tests check that such a reading is never allowed. It is a starting point, not a
classifier.

## The agent's fields

The classifier of the governed agent reads these fields. A rule compares a category with the values listed
here and no others. A value outside them, or a misspelled one, is refused when the agent loads the policy
(`policy:out-of-domain`, cause 160). Some values depend on something that is not in the rules file, and the
last column says where it is set.

<!-- fields:begin (generated by tools/gen_rules_reference.py; do not edit by hand) -->
| field | kind | values | what it reads |
|---|---|---|---|
| `classifier_version` | int | a whole number | the classifier's version, which a starter bounds with min and max to the version it was made for |
| `tool` | category | `list_dir`, `read_file`, `write_file`, `delete_path`, `run_command`, `git`, `connect`, `unknown` | the tool the call uses |
| `path_scope` | category | `none`, `workspace`, `outside`, `unknown` | the worst path the call names, which is none, inside the workspace, outside it, or not read |
| `path_in_toolchain` | bool | true or false | a named path resolves into a toolchain directory (/usr, /opt, /etc and the language toolchains under the home directory) |
| `path_control` | bool | true or false | a named path is one of the agent's own controls (.claude/, .mcp.json, .git/config, .git/hooks/, CLAUDE.md, CLAUDE.local.md, AGENTS.md, the program its hook runs, or a directory that holds one) |
| `path_glob` | bool | true or false | a named path is a pattern (* ? [ ] { }), not one exact path |
| `path_traversal` | bool | true or false | a named path has a .. component |
| `path_symlink` | bool | true or false | a named path passes through, or ends at, a symbolic link |
| `command_class` | category | `none`, `read_only`, `mutating`, `network`, `git`, `unknown` | what a run_command does, which is read only, change files, reach the network, run git, or not read |
| `kill_by_pattern` | bool | true or false | the call signals processes chosen by a name or pattern, not by one process id |
| `git_op` | category | `none`, `local_read`, `local_write`, `mutating`, `push`, `network`, `unknown` | the git operation, which is a local read, a local write, a change that cannot be undone, a push, a network operation, or not read |
| `remote_class` | category | `none`, `allowed`, `other` | a push's remote, allowed when it is in the classifier's `Config.allowed_remotes`. No command sets that list today, so every push reads other |
| `net_dest` | category | `none`, `model_api`, `allowed_host`, `other`, `unknown` | where a connect goes, which is the model's own API, a host the owner listed with `agent run --allow-host` (not part of the signed policy), another host, or one that is not read |
| `proc_class` | category | `none`, `single`, `tree`, `unknown` | what a run_command needs of the process table, one process or a tree. The limit is `agent run --max-processes` |
| `zone_reach` | category | `none`, `protected`, `unknown` | a change that reaches code in one of the owner's zones (`agent zones set`), or whose reach is not known |
| `session_protected_changes` | category | `none`, `some` | this session already made a change whose zone_reach was not none |
| `session_shell_runs` | category | `none`, `few`, `many` | the shell commands this session already ran, none, few (below 20) or many |
<!-- fields:end -->

A policy may declare fewer fields than this, and the agent decides with the ones it declares. It needs these
to do more than decide a call:

<!-- required:begin (generated by tools/gen_rules_reference.py; do not edit by hand) -->
* `path_scope`, since the sandbox profile is projected from it, and an allowed shell call is refused without one (cause 129)
* `command_class`, since the sandbox profile is projected from it, and an allowed shell call is refused without one (cause 129)
* `git_op`, since the sandbox profile is projected from it, and an allowed shell call is refused without one (cause 129)
* `path_control`, since without it no rule can refuse a change to a control file (cause 128)
* `net_dest`, since without it no rule can refuse a connection (cause 130)
<!-- required:end -->

Every starter declares all of them. `prismpath agent status` and `prismpath agent doctor` report a recorded
policy without `path_control`, and an allowed shell call under a policy without the first three is refused
because its sandbox cannot be built.

## What the rules cannot say

* A field cannot be compared with another field, and a word cannot be ordered with `<` or `>`.
* A rule cannot read the engine's own counters (`visits`, `error_count`).
* Conditions nest at most 50 levels deep.
* A rule cannot count, add, or look at text inside a value, such as a path prefix. The classifier
  turns that kind of fact into a field.
* A route literally named `refuse` or `escalate`, and a target written as a code like `refuse_105`,
  are not accepted. Name the cause.
* A field declaration is trimmed of spaces at its ends, so an image whose declaration has them cannot
  be written as rules.

For the full grammar see [authoring.md](authoring.md), and for what the core checks see
[spec-verified-core.md](../design/spec-verified-core.md).

## The causes a rule names

These are the registered causes of the routing class, the decisions a policy makes. `prismpath policy causes
--all` lists every registered cause.

<!-- causes:begin (generated by tools/gen_rules_reference.py; do not edit by hand) -->
| code | cause | meaning |
|---|---|---|
| 32 | `route:no-matching-edge` | no deterministic edge matched (hold for stateful, refuse for admission) |
| 33 | `route:below-human-floor` | semantic confidence below the calibrated floor |
| 34 | `route:needs-human` | worker explicitly requested a human |
| 35 | `route:max-steps` | walk exhausted the signed step bound |
| 36 | `route:stuck` | non-terminal node with no viable edge |
| 37 | `route:contract-violation` | worker output violated the declared contract |
| 99 | `reading:unreadable` | the reading is not a canon/2 document |
| 100 | `reading:not-object` | the reading is a canon/2 document that is not an object |
| 102 | `reading:not-canonical` | the reading reads as canon/2 but is not its canonical spelling |
| 104 | `agent:unclassifiable` | an agent tool call the classifier could not map onto the policy's fields; refused, never run |
| 105 | `agent:kill-by-pattern` | an agent command that signals processes chosen by a name pattern rather than by one process id |
| 106 | `agent:network` | an agent command or git operation that would reach the network |
| 107 | `agent:toolchain-write` | an agent write or delete into a toolchain directory |
| 108 | `agent:glob-path` | an agent write or delete whose path is a pattern, not one exact path |
| 109 | `agent:path-traversal` | an agent write or delete whose path climbs with a .. component |
| 110 | `agent:symlink-path` | an agent write or delete whose path passes through a symbolic link |
| 111 | `agent:outside-workspace` | an agent file operation whose resolved path lies outside the workspace |
| 112 | `agent:shell-mutation` | an agent command that changes files or processes outside the exact path file tools |
| 113 | `agent:push-escalated` | an agent git push to a remote class the policy does not allow; escalated to the owner and not run |
| 114 | `semantic:harm` | a model reply or proposed call whose text reaches the policy's harm threshold against the pinned harm centroids; refused, not routed |
| 115 | `semantic:intent-mismatch` | a proposed call the floor would allow whose action does not fit the task's intent class at sufficient margin; escalated to the owner and not run |
| 116 | `semantic:probing-episode` | a proposed call in an episode whose refused proposals were labelled boundary probing the registered number of times; escalated, not run, and the agent is stopped |
| 117 | `population:cap-exceeded` | a replication request beyond the population cap, the lineage quota, the count one request may ask for or the generation depth; refused and nothing is created |
| 118 | `population:rights-escalation` | a replication or evolution that would give its subject a right the parent lacks, a key other than a fresh instance key, or a policy other than the operator's signed one |
| 119 | `population:lineage-unknown` | a population request whose issuer is not a live member whose lineage traces through receipts to the operator's root |
| 120 | `population:evaluation-missing` | an evolution step without a passed canary evaluation of that exact version against the adversary set |
| 121 | `population:stop-resisted` | a request that would protect an agent from a stop or restart an agent the operator stopped; refused |
| 122 | `population:lineage-escalated` | a request from a lineage whose receipted refusals reached the registered count; escalated, not run, and the lineage is stopped as a group |
| 123 | `population:target-not-own` | a member's replication whose parent is not that member, or its evolution of a member outside its own subtree; refused and nothing changes |
| 124 | `agent:unreadable-asked` | an agent tool call whose tool or command the classifier cannot read, under the default policy that asks the person; escalated and not run |
| 125 | `agent:shell-mutation-asked` | an agent shell command that changes files, with every path inside the workspace and none of the earlier refusals holding, under the default policy that asks the person; escalated and not run |
| 126 | `agent:hook-error` | the governed agent hook could not decide a tool call (input that does not read, a missing or broken key, a recorded policy that does not verify, or an error of its own); refused and not run, never allowed |
| 127 | `agent:change-asked` | an agent call that would change files or local git state inside the workspace, with none of the earlier refusals holding, under the review policy that asks the person about every change; escalated and not run |
| 128 | `agent:control-write` | an agent call that would change one of the governed agent's own control files inside the workspace (its settings, its hook scripts, its MCP configuration, or the program its installed hook runs), by a path that resolves onto it; refused and not run, under every starter policy |
| 129 | `agent:sandbox-unavailable` | an allowed agent shell command that could not be run inside the sandbox compiled from the signed policy (the profile did not compile, or the sandbox program is missing); refused and not run, never run without the sandbox |
| 130 | `agent:net-refused` | an agent connection to a destination that is not the model's own API (a host the classifier reads as other, as an allowed host a starter policy does not list, or cannot read, or a port outside 1 to 65535); refused and not opened, under every starter policy |
| 131 | `gateway:request-refused` | an HTTP request to a resource behind a PrismPath gateway that the gateway's policy refuses, or that the gateway cannot read, decide or receipt (a request it cannot read is never forwarded); answered with a 403 and not forwarded |
| 132 | `agent:zone-asked` | an agent call that would change a file that reaches code in one of the owner's zones, or whose reach is not known (no zone information point answered, or the file is not one it can read), with none of the earlier refusals holding, under every starter policy; escalated and not run |
| 133 | `agent:session-change-asked` | an agent call that would change a file inside the workspace, commit, or push to an allowed remote, in a session that already made a change to code in one of the owner's zones (a change whose reach was protected or not known, asked about or let through) or whose history could not be read, with none of the earlier refusals holding, under the session starter policy; escalated and not run |
| 134 | `agent:session-shell-asked` | an agent shell command that would run without asking (a read only command or a local git operation inside the workspace), in a session that already ran many shell commands or whose history could not be read, with none of the earlier refusals holding, under the session starter policy; escalated and not run |
| 166 | `dist:floor-rate` | a request the action floor would have allowed, escalated because the signed rate of floor allows is spent, or an operator's answer refused past its signed answer rate |
<!-- causes:end -->
