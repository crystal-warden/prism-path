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
field.kill_by_pattern: bool
---
## core_decision
Rules are read from the top. The first one that holds decides.

-> refuse agent:unclassifiable: when tool == "unknown" or path_scope == "unknown"
-> refuse agent:kill-by-pattern: when kill_by_pattern
-> allow: when tool == "read_file" and path_scope == "workspace"
```

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
reader and changes nothing.

## A rule

A rule says what happens and when.

```
-> refuse agent:network: when command_class == "network"
```

What happens is one of three things.

* `allow` runs the call, in the sandbox.
* `refuse <cause>` never runs it. The cause is a registered name such as `agent:network`.
* `escalate <cause>` holds the call for a person and does not run it.

The causes are listed in `prismpath/kernel/causes.py`. A name that is not registered is an error, so a
typo cannot slip into a signed policy. You cannot make up a new cause in a rules file.

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
above, a misspelled cause on line 11 gives

```
prismpath policy compile: my_rules.rules.md:11: agent:kill-by-patern is not a registered cause name; did you mean agent:kill-by-pattern?
```

With that fixed, `tool == 1` on line 12 gives

```
prismpath policy compile: my_rules.rules.md:12: the rule compares a field with a value of another kind (policy:kind-mismatch: field tool)
```

Nothing is written until the file compiles. The compiler also warns about a rule that no call can
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
