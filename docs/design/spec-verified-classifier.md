# The verified classifier: the syntactic half of the governed agent's reading

*Branch `classifier-proof`, 2026-11-17. Companion to [the verified core](spec-verified-core.md). Owner decision
of 2026-11-17: prove the syntactic part, keep the disk facts as observations bounded by the sandbox, and accept
a narrower grammar where needed (what it does not read is `unknown`, which `agent_default` escalates).*

## 1. Why

The core decides one reading against one signed policy, and what is proved about the decision is proved about
the reading it is given. Whether the reading says truthfully what a call would do is the classifier's job
(`prismpath/agent/classifier.py`) and, for Claude Code and MCP, the mapping's job (`claude_code.py`,
`mcp_map.py`). A call read as `read_only` when it deletes files would be allowed by a correct core. Until this
branch the classifier stood on its own unit tests. It now has the core's status for the part of its work that
is a function of text: a Lean definition, theorems about it, and the Python held to the definition by a
differential harness.

## 2. What is a function of text and what is not

A reading has fourteen fields. Every one is computed from the call's text, except four facts per named path,
which are read off the disk:

| read off the text (modelled and proved) | read off the disk (observed, not proved) |
|---|---|
| the tool, and the argument schema of each tool | whether a path resolves inside the workspace (`path_scope` workspace or outside) |
| the command class of an argv: the program sets, the installers, `python -m pip`, `find`, `sed -i`, `sort -o`, `tree -o`, a URL in an argument | whether it resolves or normalizes into a toolchain directory (`path_in_toolchain`) |
| `kill_by_pattern`: pkill and killall, a kill not by process id, `xargs kill`, a kill inside the argument of a program that runs programs | whether it passes through a symbolic link (`path_symlink`) |
| `git_op` and `remote_class`: every subcommand set, the listing forms of tag and branch, the unsafe options, the remote of a push | for a Bash command: whether `cwd` is inside the workspace, whether it is the workspace, and whether a bare word names something in `cwd` |
| `path_glob`, `path_traversal`, and the syntactic check of a path (non empty, no NUL, at most 4096 characters, else scope `unknown`) | whether it resolves, or normalizes, onto one of the agent's own control files (`path_control`, section 4.3) |
| a home path (first component `~` or `~user`) is outside the workspace, never expanded, never a glob by itself | |
| which paths a call names, and how their facts merge (the worst scope, any flag) | |
| the Claude Code mapping: Read, Write, Edit, MultiEdit, NotebookEdit, Glob, Grep, LS, Bash; the workspace from `CLAUDE_PROJECT_DIR` or `cwd`; relative paths against `cwd`; the `/workspace` spelling | |
| the MCP mapping: the classifier's own tools and the reference filesystem server's | |

The Python now draws the same line. `classifier.disk_facts(raw, config)` is the only function of the
classifier that reads the disk, and `claude_code._inside`, `_same_dir` and `_exists` the only ones of the
mapping. The model takes their answers as inputs: what is proved is proved for every value they can take.

Between classification and execution the workspace can change. That race, a symbolic link made after the
reading, and every other disk fact are bounded by the sandbox (`integrations/governed_harness/sandbox.py`), not
by anything proved here.

## 3. The model (formal/Classifier/)

| file | what it holds |
|---|---|
| `Basic.lean` | strings as character lists and the operations the Python uses on them, each as Python defines it (`str.split("/")`, `str.split()` over Python's whitespace, `posixpath.basename` and `dirname`, `partition("=")`, the `_URL` search); every program and subcommand set word for word; the reading and its document |
| `Classify.lean` | `classify disk remotes call`: path facts, `_path_like_args`, the kill readers, `command_class`, `git_listing`, `git_facts`, the schema, the whole call. `plan` computes the reading before its path facts and the paths it names, and `classify` merges their facts, so the disk is consulted at exactly the paths `plan` names |
| `Hook.lean` | the plain word grammar (`splitPlain`), `claude_code.hook_call` and `mcp_map.classifier_call` |
| `Shape.lean` | `fits`: a field definition that accepts what every reading holds for its name |
| `Scan.lean`, `ScanTheorems.lean` | the hazard scan of a Bash command the grammar does not read (section 4.1) and its theorems |
| `Theorems.lean` | the theorems of section 5 |
| `Axioms.lean` | the axiom audit, which fails the build if any theorem depends on more than `propext`, `Classical.choice` and `Quot.sound` |
| `Main.lean` | the oracle, `lake exe classifier-oracle` |

The model reads a call as the core's own JSON value (`Core.J`). Its strings are Lean strings, which hold
Unicode scalar values only. A Python string can hold a lone surrogate (JSON's `\ud800` escape spells one); such a
call is outside the model's domain, and the Python reads it unknown (`classifier.scalar`, in `classify`,
`hook_call` and `classifier_call`).

## 4. The narrowing (behaviour change)

Two places read more than a proof can promise, and were narrowed to the model, as the owner allowed. The
alternative, keeping the Python and proving only a subset, would leave a part of the Python's reading with no
definition to hold it to; narrowing makes the model the whole specification of the syntactic reading, so the
harness compares every input.

**The Bash grammar replaces `shlex.split`.** A command is words separated by spaces and tabs. A word is a run of
plain characters (ASCII letters and digits and `- _ . / , : = + @ % * ? [ ] }`), single quoted text and double
quoted text, joined. Quoted text holds plain characters, spaces, tabs, `~ { # ^` and the other quote. On this
grammar the shell and the reading agree: there is no escape, no expansion but globbing (which the classifier
flags), no comment and no history expansion. Everything else reads unknown: a backslash, `~ { # ! ^` outside
quotes, any control or non ASCII character, a quote left open, and, as before, a shell operator, a later word
that starts with `~` or holds `{`, a `cwd` outside the workspace, an empty command. `~` anywhere unquoted is now
unknown because bash expands it after `=` in an argument (`a=~/x`), which shlex did not see.

**ASCII where the Python read Unicode.** A signal (`-9`, `-KILL`) is matched in full and in ASCII (`re.ASCII`,
`fullmatch`; `$` used to accept a trailing newline), a process id is ASCII digits, the `pkill`/`killall` word
boundary is ASCII, and `git tag -nN` takes ASCII digits. Each is the stricter reading: a non ASCII digit is no
longer a process id, so `kill ١٢` reads as a kill by pattern, and ASCII word boundaries are a superset of
Unicode ones, so `épkill` inside `sh -c` is now caught.

### 4.1 The hazard scan (owner decisions, 2026-11-17)

The grammar alone moved hazards outside it from refuse to ask. The owner decided hazards must stay refused, so a
Bash command that reads unknown is scanned on its raw text (`claude_code.hazard_scan`, `formal/Classifier/Scan.lean`),
after the scalar check. The text is first stripped of backslashes and both quotes, so `pk\ill` and `p'k'ill`
are scanned as the shell joins them. A word is a maximal run of ASCII letters, digits and `_`; a token is a
piece of the text split at Python whitespace, shell operators and `= : , { }`. The rules, each stated on the text
alone:

| evidence | rule | reading field |
|---|---|---|
| kill | a word is `pkill`, `killall` or `kill` | `kill_by_pattern` |
| network | a word in `NETWORK` (curl, wget, ssh, scp, sftp, nc, ncat, netcat, telnet, ftp, ping, ping6, dig, nslookup, host, traceroute, tracepath, socat, apt, brew, aria2c, http, https, lynx, w3m, links, rsync, torsocks) inside a token that gives no path evidence; or a URL scheme (`[A-Za-z][A-Za-z0-9+.-]*://`); or an installer token (by base name: pip, pip3, npm, yarn, pnpm, cargo, gem, go, apt, apt-get, brew, dnf, yum, apk, pipx, conda, port) followed in any later token by one of its fetch words (`install`, `download`, `wheel`, `i`, `add`, `ci`, `update`, `fetch`, `search`, `publish`, `get` as `classifier.INSTALLERS` lists them, and `install` or `add` for the system managers) | `command_class` network |
| outside | a token starts with `~`, or starts with `/` and is neither the workspace nor lexically below it | `path_scope` outside |
| traversal | a token has a `..` component | `path_traversal` |
| toolchain | a token has a `.toolchain` component | `path_in_toolchain` |
| glob | a token holds `* ? [ ]` | `path_glob` |
| long | a token is longer than 4096 characters or holds a NUL (the classifier's own path check) | `path_scope` unknown |
| control | a token that, as a path against the hook's `cwd`, the disk says is a control path (section 4.3), in a command that is not read-only (a `>` to a file, or a file changing program; section 4.3 lists them) | `path_control`, and `command_class` mutating |
| git | after a token whose base name is `git`: an unsafe option (`--exec`, `--upload-pack`, `--receive-pack`, `-c`, `--config`, `--git-dir`, `--work-tree`, `-C`) or a subcommand the classifier does not know (unknown); a network subcommand (network); a mutating subcommand or `reset --hard` (mutating); `push` (push, to a remote that is not allowed); `remote` with anything but `-v` (unknown). The most severe over every git token wins, in the order unknown, network, mutating, push | `git_op` (and `remote_class` other for a push) |

A path token is one that gives outside, traversal, toolchain, glob or long evidence (control evidence is read per token from the disk and is not a path token in this sense). A network word inside a
path token does not count (`~/.ssh/id_rsa` is a path, so `cat ~/.ssh/id_rsa` refuses as outside the workspace, not
as network). Any path evidence also makes `command_class` mutating (a command that cannot be read is taken to
change files), so the path refusal rules, which apply to changes, fire. When the scan finds nothing the reading is
the unknown reading exactly as before and the command asks. Absence of evidence means only that the scan found
nothing: variables, command substitution and aliases can still hide a hazard, which is why such a command asks
rather than runs.

What it proves (`ScanTheorems.lean`): each rule as stated (`scan_kill`, `scan_network`, `scan_outside`,
`scan_traversal`, `scan_toolchain`, `scan_glob`, `scan_long`, `scan_git`, with the evidence and git lemmas
`networkEvidence_of_word`, `installerEvidence_of`, `gitScan_ge`, `gitOpOf_unsafe`, `gitOpOf_push`,
`gitOpOf_network`, `gitOpOf_mutating`, `gitOpOf_reset_hard`, `gitOpOf_unknown_sub` and the rest); the label
(`network_word_in_path_only`); no evidence, no change (`scan_none`, `hookReading_unchanged`); and **the scan only
ever adds refusals** (`hookReading_only_adds_refusals`). Under a policy whose scan readings are safe (`scanSafe`:
none is allowed, and every one but a push alone is refused, computed by the oracle's `--policy` mode with the
core's own evaluator over the 1,279 readings the scan can give, proved to be all of them by `scanReading_mem`), a hook
reading is the mapped call's reading unchanged, or one the policy never allows and refuses unless the scan found
only a push. A push alone asks, as the unknown reading did. All three shipped agent policies are `scanSafe`, and
the harness requires it. The scan never runs on a command the grammar reads, so it cannot change an allowed call.

### 4.2 What changed, measured

On the 120 written hook inputs, against main before the grammar: three changed, all from ask to refuse:
`kill-3` (`sh -c 'kill $(pgrep -f 987654)'`, 105), `shell-tilde` (`cat ~/.ssh/id_rsa`, 111, outside the workspace)
and `shell-brace` (`cat {/etc/passwd,notes.txt}`, 111). The second scan changed one recorded answer, the label of
`shell-tilde`, from 106 to 111. The 51 adversary probes, the starter tables and the guide tests are otherwise
unchanged; every hazard stays refused.

On 20,000 generated Bash commands against a real workspace (the same set throughout):

- 6,409 are outside the grammar. **None of them is allowed.** No command is allowed that main did not allow, and
  no command the first scan refused now asks.
- Of the 605 that main refused and the grammar alone moved to ask, **572 are refused again**: 217 network (106),
  137 kill by pattern (105), 85 outside (111), 43 glob (108), 40 traversal (109), 33 unclassifiable (104: an
  unknown git operation or an over long path), 11 toolchain (107), 6 git mutation (112). The cause can differ from
  main's (the scan's first refusal rule that holds).
- Of the 76 that still asked after the first scan, 43 refuse now: 18 unclassifiable (104), 11 glob (108), 8
  network (106, installers and git network), 6 git mutation (112).
- 33 still ask: 16 hold a lone surrogate (outside the model's domain, never scanned), 14 reach outside the
  workspace only through a symbolic link (a disk fact the text does not show), and 3 are harmless forms main read
  differently through shlex (`git stash\<TAB>`, `"git" add<NBSP>-ofile -f`, `\unzip diff "-k" }`).

`CLASSIFIER_VERSION` stays 1: the change makes readings more conservative and every signed policy bounds the
version to 1.

### 4.3 The agent's own controls (`path_control`, cause 128)

The agent must not rewrite the controls that govern it, or the files that shape how it behaves. A path the call
names reads `path_control` when, resolved (`realpath`) or normalized (`normpath`) and compared **case insensitively
on every platform** (Unicode NFC and `casefold`), it is any of:

- anything under `.claude/`, `.claude` itself included (settings, local settings, `hooks/`, `commands/`, `agents/`,
  `skills/`);
- `.mcp.json`, `.git/config`, and anything under `.git/hooks/` (persistence and hook execution);
- a file or directory named `CLAUDE.md`, `CLAUDE.local.md` or `AGENTS.md`, at any depth;
- the program the installed PrismPath hook runs, when that program is inside the workspace (the first word of a hook
  command in `.claude/settings.json`);
- **holders**, the workspace root, `.git`, a directory that holds a hook program, and a directory with a `CLAUDE.md`,
  `CLAUDE.local.md` or `AGENTS.md` anywhere below it. A holder is a control target **only where a call removes or
  moves it** (`destroy_paths`, below): `rm -r .`, `rm -rf ./`, `rm -rf .git`, `mv . x`, `find . -delete`, `git rm -r .`,
  `git clean -fd .`, `rm -rf docs/` with a `docs/CLAUDE.md`. Writing into a holder (`cp x .`, `tee ./new`, a redirect
  to a new file, `git add .`, `pytest .`) names the directory without changing it, and is decided by the file
  written, as before. The search below a directory examines at most `WALK_LIMIT` (20,000) entries and does not enter
  `.git`, `node_modules`, `target`, `.venv`, `venv` or `__pycache__` directories it meets on the way; past the limit it
  stops, and the answer is the one found so far;
- **a hard link to any of these**: a file whose device and inode match a control file that exists (`os.stat`
  `st_dev`/`st_ino`, checked only when the path's link count is above one). A link made after the call is classified is
  the sandbox's job, not the classifier's, like any change to the disk between classification and execution.

Case insensitivity is the conservative choice: macOS and Windows name one file by several spellings (`.CLAUDE`), and
on a case sensitive filesystem the folding refuses a few more paths than it must (`.Claude/x`), never fewer.

Which paths those are is read off the disk at the moment of the call, like a toolchain directory
(`classifier.disk_facts`, `DiskFacts.control` and `DiskFacts.holder`), so the model takes it as an input like the other disk facts, and a
`..` component or a symbolic link does not hide the file. The rule is the same in all three starters, placed among the
refusals that hold whatever else does:

    -> refuse agent:control-write: when (tool in ["write_file", "delete_path"] or command_class == "mutating"
                                        or git_op in ["local_write", "mutating"]) and path_control

It covers every way the classifier reads a change: Write, Edit, MultiEdit and NotebookEdit, the MCP file tools of
`mcp_map.py`, and the Bash commands the plain word grammar reads (`rm`, `mv`, `cp`, `mkdir`, `sed -i`, `tee` and the rest
of `MUTATING`), as source or destination, since the classifier does not tell the two apart. **What removes or moves** is defined by the call, not the disk (`classifier.destroy_paths`, `destroyPaths` in Lean):
the delete tool's path; every path of `rm` and `rmdir`; every path of `mv` but the last (the destination); the paths
of `find ... -delete`; and the paths of `git rm` and `git clean`. For those paths `path_control` is also set when the
path is a holder (`classifyD` in Lean: the reading of `classify` with only `path_control` changed). A read is decided
as before (`ls .`, `cat CLAUDE.md`, a Read of `.claude/settings.json`). A refusal is receipted with its cause like any other, so it is an
observation: a later policy proposal may read these refusals, and they never change the policy on their own.

**Commands outside the plain grammar.** `echo x > .claude/settings.json` or `printf y >> .mcp.json` has an operator
the grammar does not read, so it maps to the unknown call; the hazard scan (section 4.1) now also looks for a control
path. Its evidence is a token that, as a path against the hook's `cwd`, the disk says is a control path, in a command
that is not read-only. A command is not read-only, by its text, when it holds a `>` that sends output to a file (not a
duplicated descriptor such as `2>&1` or `>&2`, and not `>/dev/null`) or names a program that changes files (`rm`,
`rmdir`, `mv`, `cp`, `ln`, `chmod`, `chown`, `chgrp`, `touch`, `mkdir`, `dd`, `truncate`, `shred`, `tee`, `install`,
`unlink`, `tar`, `unzip`, `zip`, `gzip`, `gunzip`, `patch`, `vim`, `vi`, `nano`, `ed`, a `find` with an effect, a `sed
-i`, a `sort -o`, a `tree -o`, or `git` with a subcommand that writes). An interpreter or a build tool (`python`,
`pytest`, `make`) is not one, because what it writes is not in the text: `python -m pytest . 2>&1 | tail` still asks
and is not refused as a change to the root. The scan's reading is a change that names a control path
(`command_class` mutating, `path_control`), so every shipped starter refuses it with 128 and, as for every scan
reading, it never allows. The scan does not follow a `cd` (`cd sub && echo x > settings.json` names `settings.json`
against the hook's `cwd`); it catches `cd .claude && echo x > settings.json` because the token `.claude` is itself a
control path in a command that redirects. A command that writes through an interpreter (`python -c "open(...)"`) is not
read by the scan and asks, as any command outside the grammar does.

What it proves (`Control.lean`, `ScanTheorems.lean`): `classify_control`, a path the call names that passes the
syntactic check and that the disk says is a control path gives `path_control`; `control_refused` and
`change_on_control_refused`, under a policy the oracle's `--policy` mode reports as `control_refused` (`controlSafe`:
every one of the 2,580,480 readings with `path_control` that is a change is refused, computed with the core's own
evaluator and proved to be all of them by `control_refused`), a change that names a control path is refused, whatever
the call; `write_control_refused`, `delete_control_refused` and `run_mutating_control_refused` for the write tool, the
delete tool and a file changing command; `classify_holder`, `change_on_holder_refused`, `delete_holder_refused`,
`destroyArgs_rm` and `run_destroy_holder_refused` for a removal or a move of a holder (the holder fact is a disk fact
like the control fact, and only `destroyPaths` makes it count); and for the scan `scan_control` (control evidence gives a reading that is a
change naming a control path), `scan_control_refused` (under every policy the oracle reports as `scan_refused`, that
reading is refused), with `controlEvidence_of`, `controlEvidence_of_holder`, `writeEvidence_of_redirect` and `writeEvidence_of_writer` for the two
halves of the evidence. All three shipped agent policies are `controlSafe` and `scanSafe`, and the harness requires it.
The case folding, the inode check, the directory search and which paths are control are disk facts, an input of the
model, so they are exercised by the tests and the harness's real disk, not proved.

Writing into the root or a holder keeps the verdict it had before the control rule (`git add .` and `git checkout .`
allow, `pytest .` and `cp x .` ask under `default`, as on the commit before it). In the scan, which cannot tell a
source from a destination, `mv x .` in a command outside the grammar counts as a move of `.`.

Not covered, on purpose: a command that changes a control file through an interpreter or a build tool; a `cd` followed
by a relative path in a command outside the grammar; a hard link to a `CLAUDE.md` below the first 20,000 entries; a
control file that does not exist yet and is hard linked after the call (the sandbox's job).

### 4.4 The network (`net_dest`, `proc_class`, cause 130)

The sandboxed agent reaches the network only through a proxy that asks the policy about each connection.
Classifier version 2 adds the tool `connect`, two reading fields and
one cause. The proxy does not feed the classifier yet (a later package does); this package defines the call and the
reading.

A connect call is `{"tool": "connect", "args": {"host": str, "port": int}}`. The port is a true integer (a bool, a
float or a string fails the schema and the call reads unknown). The Claude Code hook and the MCP mapping never make one,
and an MCP tool named `connect` reads unknown (the mappings pass through only the classifier's original six tool names).
Its reading holds `tool` `connect`, `net_dest`, and every other field at its default.

| `net_dest` | when |
|---|---|
| `unknown` | the host is not read (`host_ok`) or the port is outside 1 to 65535 |
| `model_api` | the host is in the constant `MODEL_API` table (`api.anthropic.com`, `platform.claude.com`) and the port is 443 |
| `allowed_host` | the host is one the owner listed (`Config.allowed_hosts`) and the port is 443 |
| `other` | every other readable host and port |

A host is read when it is lower case ASCII letters, digits, `-` and `.`, at most 253 characters, has no empty label
(no leading or trailing dot, no `..`), each label at most 63 characters and not starting or ending with `-`, and its last
label starts with a digit only when the whole host is a dotted quad of decimal octets without leading zeros. So a trailing
dot, an upper case letter, userinfo (`@`), a port or a path in the host, a bracketed or colon form of an address, and the
short forms of an IPv4 address (`127.1`, `2130706433`, `0x7f.0.0.1`) are all `unknown`. A canonical dotted quad is `other`
unless the owner listed it; the proxy refuses a private or loopback result by itself. The model's table is classifier
code, so a change to it is a version bump and a signed image, never configuration.

`proc_class` is `none` for every tool but `run_command`. For a command it is `tree` for a program that runs children (every
wrapper, a builder, a test runner, a package manager, `find` with an exec action), `single` for any other program the
classifier knows, and `unknown` for a program of the workspace, a privilege program, anything else, an argv that does not
read, and every reading the hazard scan gives. No starter reads it yet. It exists so a sandbox profile can take its process
limit from the allow set.

Every starter refuses a reading with `net_dest` `allowed_host`, `other` or `unknown`, and a `connect` that names none, with
cause 130 `agent:net-refused`, and allows `connect` to `model_api`. The starters list no allowed host, so they refuse
`allowed_host` too; an owner who lists hosts writes the rule that allows them. The existing readings keep their verdicts:
none of the old rules reads either new field, and every call that is not a connect has `net_dest` `none`.

What it proves (`Net.lean`): `netDestOf_model_api` and `netDestOf_allowed`, a connect reads `model_api` or `allowed_host`
only for a host of the table or of the owner's list, on port 443; `netDestOf_other`, any other host reads `other` or
`unknown`; `netDestOf_unreadable`, an unreadable host or a port outside 1 to 65535 reads `unknown`; `net_refused`, under
a policy the oracle's `--policy` mode reports as `net_refused` (`netSafe`: every one of the 5,160,960 readings that is a
`connect` naming no class, or has `net_dest` `other` or `unknown`, is refused, computed with the core's own evaluator),
every such reading is refused; and `connect_other_refused` and `connect_unreadable_refused`, so a connect to a host that
is neither in `MODEL_API` nor on the owner's list, whatever the host and port, is refused under every `netSafe` policy. All
three shipped agent policies are `netSafe`, and the harness requires it. The owner's list reaches the model in its
`remotes` input as `-host:NAME`, which no push remote can spell.

Not proved: that the proxy decides every connection it opens through this reading, and that the sandbox leaves no other
route. The reading of a host is text, held to the Lean by the differential harness over a corpus of odd hosts (case,
trailing and leading dots, userinfo, ports and paths in the host, IP literals in every form, labels at and past their
limits, non ASCII) and ports (0, 65535, 65536, negatives, past 2 to the 53rd, a bool, a float, a string).

### 4.5 Home paths in the file tools

A path argument of Read, Write, Edit, MultiEdit, NotebookEdit, Glob (path and pattern), Grep and the filesystem
server's tools whose first component is `~` or `~user` is read as outside the workspace (`path_scope` outside, cause
111), the same as the Bash scan reads a `~` token. The hook maps such a path to the call as it is written, where it
used to map it to unknown (asked, cause 124). The classifier never expands `~`, so the rule does not depend on what
`HOME` is. One rule was chosen, always outside. Reading `~` against `HOME` when `HOME` is inside the workspace would
make a reading depend on an environment variable that the hook, the sandbox and the tool may not share, and the Bash
scan already reads `~` as outside with no such exception, so the two cannot disagree. A `~` that is not the first
component (`foo/~bar`) is an ordinary name. A leading `~` no longer sets `path_glob`, since it is a home path and not
a pattern, which also lets a write to `~/x` refuse with 111 and not 108. Claude Code's hooks document says it expands
`~` in `file_path` of Read, Write and Edit before the hook runs, so the hook should not see one there. Its Glob and
Grep `path` fields are not documented as expanded, and the classifier does not rely on either.

## 5. What is proven

Every theorem is in `formal/Classifier/Theorems.lean`, builds with no unfinished proof, and depends on the
standard axioms at most (`Axioms.lean` enforces it at every build).

| theorem | statement in words |
|---|---|
| `classify_local` | **Locality, and so determinism.** The reading is a function of the call, the allowed remotes and the disk's observations at the paths `diskQueries` names; two disks that agree there give the same reading |
| `hookCallIn_local` | the Claude Code mapping depends on the disk only through the facts `hookQueries` names |
| `bashArgv_operator` | **any shell operator** (`\| ; & $` backtick `< > ( )`, CR, LF) anywhere in a Bash command makes it unreadable |
| `splitPlain_outside`, `bashArgv_outside` | **any character outside the grammar** makes it unreadable |
| `splitPlain_words_chars` | the grammar's words hold only characters of the command, so (with the operator check) no word the mapping reads holds an operator |
| `bashArgv_tilde_brace` | a later word starting with `~` or holding `{` makes it unreadable |
| `hook_bash_unknown`, `classify_unknownCall` | so such a hook input maps to the unknown call, whose reading is the unknown reading |
| `commandClass_read_only`, `classify_read_only` | **nothing outside the model's `READ_ONLY` list reads `read_only`**: a `read_only` reading comes from an argv whose program is in that list, in neither `NETWORK` nor `PRIVILEGE`, not git, with no URL in any argument. This is a fact about the model's list. It does not prove a listed program cannot write a file or run a command (`sed` and `sort` could, and were on the list); `prismpath/tests/test_read_only_runs.py` runs every listed program to check that |
| `privilege_unknown`, `url_network`, `workspace_program_mutating` | a privilege program is unknown; a URL in any argument is network (but for privilege, git and workspace programs); a program named by a path outside the system directories is mutating |
| `classify_traversal` | **a path with a `..` component has path_traversal**: every path a call names with a `..` component gives `path_traversal`, or the unknown scope when the path fails the syntactic check |
| `classify_glob`, `isGlob_of_char` | **a glob character gives path_glob**, in the same sense |
| `pathFacts_home`, `classify_home` | **a home path reads as outside the workspace**: a named path whose first component is `~` or `~user` gives scope outside (or unknown when it fails the syntactic check), whatever the disk says and whatever `HOME` is. A `~` that is not the first component is an ordinary name |
| `path_tool_plan`, `write_plan`, `run_command_plan`, `pathLike_mem` | which paths a call names: a path tool its path; a command that is not git every argument that is not an option, and every argument after `--` |
| `kill_pkill`, `kill_not_by_pid`, `kill_xargs`, `kill_wrapped`, `argKills_word`, `argKills_inner`, `innerKill_of` | **kill by pattern is detected for every listed form**: pkill or killall by any path; kill whose targets are not all process ids; `xargs ... kill`; a pkill or killall word, or a kill not by process id, inside an argument of a program that runs programs |
| `killArgsByPid_sound` | a kill read as not by pattern names one or more positive process ids, after at most one signal |
| `classify_kill`, `kill_only_run_command` | a well formed run_command call reads `kill_by_pattern` exactly as its argv; only a command can |
| `git_unsafe_unknown`, `git_push_remote` | an option that runs a program or moves the repository makes git unknown; a push is to an allowed remote only when its first remote word is allowed (`origin` by default) |
| `classify_unknown_tool`, `hook_unknown_tool`, `mcp_unknown_tool` | an unknown classifier tool, Claude Code tool or MCP tool reads unknown |
| `scan_kill`, `scan_network`, `scan_outside`, `scan_traversal`, `scan_toolchain`, `scan_glob`, `scan_long`, `scan_git`, `network_word_in_path_only`, `scan_none`, `hookReading_only_adds_refusals` | the hazard scan (section 4.1): each rule as stated, the path label, no evidence no change, and under every `scanSafe` policy the scan never allows and only adds refusals |
| `reading_fields` | every reading holds the fourteen fields, in canonical order, with `classifier_version` 2 |
| `accept_fits`, `boundary_accepts_every_reading`, `decide_never_contract` | **the core's boundary never refuses a classifier reading for its shape**: for a policy whose field definitions all fit, the system boundary accepts every reading, so the verdict is a route or no match, never `route:contract-violation`. The three shipped agent policies fit: the oracle's `--policy` mode computes it on each image and the harness requires it |

## 6. The oracle and the differential harness

`lake exe classifier-oracle --batch` reads one case per line: the kind (`call`, `hook` or `mcp`), the input, and
the disk facts as tables. It prints the call, the workspace and the reading the model gives, or the facts it
needs that are not in the tables. Which facts it needs is `diskQueries` and `hookQueries`, which the locality
theorems prove sufficient.

`formal/diff/classifier_diff.py` runs every case through the Python and through the oracle. The Python's four
disk functions are replaced for the run by a provider that records every fact asked; the facts go to the oracle,
and a fact the oracle needs and the Python did not ask is observed and the case run again. The real disk
provider (a throwaway workspace and decoy with links in and out) serves every written hook input
(`prismpath/tests/fixtures/claude_code_hooks.json` and the zone inputs beside it) and the 51 adversary probes (54 calls); a synthetic provider, each fact a seeded function of its key, serves the generated
calls, so every combination of disk facts meets every text. Numbers reach the oracle as 0, since no part of the
reading reads a number's value; a call with a lone surrogate reaches it as outside the domain.

The generator writes direct classifier calls, Claude Code hook inputs and MCP params: every program set, path
spellings of programs, every git subcommand and listing flag, every kill form with Unicode around and inside the
kill words, URLs, `..`, globs, home paths (`~`, `~/x`, `~root/x`, `foo/~bar`), `/workspace`, quoting of every kind, shell operators, tilde and brace words, non
ASCII and control characters, lone surrogates, wrong types, missing and extra keys, long paths and long argvs.

Result: 219 written calls, 0 disagreements; 20,000 generated calls (seed 1), 0 disagreements; 100,000 (seed 2),
0 disagreements. The harness was checked to see the Python change: dropping `ls` from `READ_ONLY`, allowing `~`
in plain words or `!` in quotes, Unicode `\d` in the signal, a Unicode `\b` around pkill, Unicode digits as
process ids, or a 4097 character path limit each gives disagreements on the 20,000 run, and so does breaking the
scan: no stripping of quotes, Unicode word characters, tokens not split at `:`, no URL rule, `?` not a glob
character, no `pip` or `npm` installer, the git severity order swapped, `reset --hard` not mutating, or the path
label turned off.

    cd formal && lake build                                     # the model, the theorems, the audit, the oracle
    python formal/diff/classifier_diff.py --cases 20000 --seed 1
    python -m pytest prismpath/tests/test_classifier_diff.py    # the CI size run

The formal workflow builds and runs both, and `tools/reproduce.sh` has the step `classifier-diff`.

## 7. What is not proven, stated as plainly

- **The disk facts.** Whether a path is inside the workspace, in a toolchain, or through a link; whether `cwd`
  is the workspace; whether a word names a file. These are observations made when the call is classified, and
  the workspace can change before it runs. The sandbox bounds that, nothing here does.
- **The shell's semantics.** The grammar of section 4 is chosen so that bash and the reading agree on it, but no
  model of bash is proved against bash. In particular a glob expands on the disk, so an argument like `*` can
  become an option word when a file of that name exists (`find *` with a file named `-delete`): the reading
  flags the glob, the policy allows it for a read only program, and only the sandbox bounds the result.
  Aliases and functions in the user's shell are outside the model too.
- **This is not a verified translation of the Python.** As with the core, the Lean is a port read against the
  source; its agreement with the code rests on the differential harness and on review.
- **What the programs do.** The sets say what a program is; that `cat` does not write is a fact about `cat`,
  not a theorem.
