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

A reading has eleven fields. Every one is computed from the call's text, except three facts per named path,
which are read off the disk:

| read off the text (modelled and proved) | read off the disk (observed, not proved) |
|---|---|
| the tool, and the argument schema of each tool | whether a path resolves inside the workspace (`path_scope` workspace or outside) |
| the command class of an argv: the program sets, the installers, `python -m pip`, `find`, `sed -i`, `sort -o`, `tree -o`, a URL in an argument | whether it resolves or normalizes into a toolchain directory (`path_in_toolchain`) |
| `kill_by_pattern`: pkill and killall, a kill not by process id, `xargs kill`, a kill inside the argument of a program that runs programs | whether it passes through a symbolic link (`path_symlink`) |
| `git_op` and `remote_class`: every subcommand set, the listing forms of tag and branch, the unsafe options, the remote of a push | for a Bash command: whether `cwd` is inside the workspace, whether it is the workspace, and whether a bare word names something in `cwd` |
| `path_glob`, `path_traversal`, and the syntactic check of a path (non empty, no NUL, at most 4096 characters, else scope `unknown`) | |
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

What changed, measured. None of the 120 recorded hook inputs (`prismpath/tests/fixtures/claude_code_hooks.json`)
and none of the governed harness's 51 adversary probes changed answer; the starter tables
(`prismpath/tests/test_agent_starters.py`) and the guide tests pass unchanged, and every hazard stays refused. On
20,000 generated Bash commands against a real workspace, 1,177 changed, every one to ask
(`agent:unclassifiable`, 124): 247 that were allowed, 324 that asked as shell mutations (125), one push that
asked (113), and 605 that were refused (104 to 112). Each of those holds a character outside the grammar, mostly non ASCII text, a backslash or
an unquoted `~`. A person is now asked about them; under `agent_rules` they are refused as unclassifiable.
`CLASSIFIER_VERSION` stays 1: the change makes readings more conservative and every signed policy bounds the
version to 1.

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
| `commandClass_read_only`, `classify_read_only` | **nothing outside the read only set is read only**: a `read_only` reading comes from an argv whose program is in `READ_ONLY`, in neither `NETWORK` nor `PRIVILEGE`, not git, with no URL in any argument |
| `privilege_unknown`, `url_network`, `workspace_program_mutating` | a privilege program is unknown; a URL in any argument is network (but for privilege, git and workspace programs); a program named by a path outside the system directories is mutating |
| `classify_traversal` | **a path with a `..` component has path_traversal**: every path a call names with a `..` component gives `path_traversal`, or the unknown scope when the path fails the syntactic check |
| `classify_glob`, `isGlob_of_char` | **a glob character gives path_glob**, in the same sense |
| `path_tool_plan`, `write_plan`, `run_command_plan`, `pathLike_mem` | which paths a call names: a path tool its path; a command that is not git every argument that is not an option, and every argument after `--` |
| `kill_pkill`, `kill_not_by_pid`, `kill_xargs`, `kill_wrapped`, `argKills_word`, `argKills_inner`, `innerKill_of` | **kill by pattern is detected for every listed form**: pkill or killall by any path; kill whose targets are not all process ids; `xargs ... kill`; a pkill or killall word, or a kill not by process id, inside an argument of a program that runs programs |
| `killArgsByPid_sound` | a kill read as not by pattern names one or more positive process ids, after at most one signal |
| `classify_kill`, `kill_only_run_command` | a well formed run_command call reads `kill_by_pattern` exactly as its argv; only a command can |
| `git_unsafe_unknown`, `git_push_remote` | an option that runs a program or moves the repository makes git unknown; a push is to an allowed remote only when its first remote word is allowed (`origin` by default) |
| `classify_unknown_tool`, `hook_unknown_tool`, `mcp_unknown_tool` | an unknown classifier tool, Claude Code tool or MCP tool reads unknown |
| `reading_fields` | every reading holds the eleven fields, in canonical order, with `classifier_version` 1 |
| `accept_fits`, `boundary_accepts_every_reading`, `decide_never_contract` | **the core's boundary never refuses a classifier reading for its shape**: for a policy whose field definitions all fit, the system boundary accepts every reading, so the verdict is a route or no match, never `route:contract-violation`. The three shipped agent policies fit: the oracle's `--policy` mode computes it on each image and the harness requires it |

## 6. The oracle and the differential harness

`lake exe classifier-oracle --batch` reads one case per line: the kind (`call`, `hook` or `mcp`), the input, and
the disk facts as tables. It prints the call, the workspace and the reading the model gives, or the facts it
needs that are not in the tables. Which facts it needs is `diskQueries` and `hookQueries`, which the locality
theorems prove sufficient.

`formal/diff/classifier_diff.py` runs every case through the Python and through the oracle. The Python's four
disk functions are replaced for the run by a provider that records every fact asked; the facts go to the oracle,
and a fact the oracle needs and the Python did not ask is observed and the case run again. The real disk
provider (a throwaway workspace and decoy with links in and out) serves the 120 recorded hook inputs and the 51
adversary probes (54 calls); a synthetic provider, each fact a seeded function of its key, serves the generated
calls, so every combination of disk facts meets every text. Numbers reach the oracle as 0, since no part of the
reading reads a number's value; a call with a lone surrogate reaches it as outside the domain.

The generator writes direct classifier calls, Claude Code hook inputs and MCP params: every program set, path
spellings of programs, every git subcommand and listing flag, every kill form with Unicode around and inside the
kill words, URLs, `..`, globs, `/workspace`, quoting of every kind, shell operators, tilde and brace words, non
ASCII and control characters, lone surrogates, wrong types, missing and extra keys, long paths and long argvs.

Result: 174 recorded calls, 0 disagreements; 20,000 generated calls (seed 1), 0 disagreements; 100,000 (seed 2),
0 disagreements. The harness was checked to see the Python change: dropping `ls` from `READ_ONLY`, allowing `~`
in plain words or `!` in quotes, Unicode `\d` in the signal, a Unicode `\b` around pkill, Unicode digits as
process ids, or a 4097 character path limit each gives disagreements on the 20,000 run.

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
