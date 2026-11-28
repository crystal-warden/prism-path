# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""PrismPath command-line interface package."""
import argparse
import os
import sys

from prismpath.cli.common import CliError, require_program, user_error as _user_error
from prismpath.cli.flows import (
    STARTER_FLOW,
    STARTER_TESTS,
    bundle_compile,
    compile_unavailable_cmd,
    contract_cmd,
    gallery_templates,
    graph_flow,
    import_cmd,
    init_cmd,
    lint_flow,
    plugins_cmd,
    portable_cmd,
    test_flow,
    validate_flow,
)
from prismpath.kernel import analysis
from prismpath.kernel.engine import run
from prismpath.kernel.parser import parse_file

_gallery_templates = gallery_templates

# Commands registered so an explicit call fails with a clear message, but withdrawn from every persona
# group and from the grouped help because this distribution cannot perform them.
WITHDRAWN_COMMANDS = () if bundle_compile else ("compile",)

# The four people who touch a PrismPath deployment, and the commands that are theirs. The help text
# is grouped by this table instead of one flat list; tests/test_cli_personas.py keeps every registered
# subcommand in exactly one group.
PERSONAS = (
    ("Process owner: author and test the policy of record",
     ("init", "validate", "test", "graph", "lint", "context", "policy")),
    ("Engineer: implement the interface once, calibrate for deployment, deliver",
     ("contract", "capability") + (() if WITHDRAWN_COMMANDS else ("compile",)) + (
      "portable", "lock", "verify", "plugins", "ci-report", "lsp", "import", "calibrate", "label", "annotate", "kappa", "centroids", "authorize", "canonicalize")),
    ("Operator: run the system day to day, swap and attest policy (Mission Control is the console; this is the scripted path)",
     ("run", "resume", "compose", "swap", "trail", "agent", "gateway", "dist")),
    ("Assessor: anchor, verify, and read the evidence",
     ("ledger", "evidence", "facet")),
)


def _grouped_help(subparsers) -> str:
    """Render the subcommands grouped by persona, one line each, from the registered parsers."""
    out = ["commands, by who runs them", ""]
    for title, names in PERSONAS:
        out.append(title + ":")
        for name in names:
            sub = subparsers.choices.get(name)
            help_text = ""
            if sub is not None:
                for action in subparsers._choices_actions:
                    if action.dest == name:
                        help_text = (action.help or "").split(". ")[0].split(": ")[0]
                        if len(help_text) > 88:
                            help_text = help_text[:85].rsplit(" ", 1)[0] + "..."
                        break
            out.append(f"  {name:<12} {help_text}")
        out.append("")
    out.append("`swap` splits by action: keygen, envelope, and pack are the engineer's setup; swap and attest are the "
               "operator's; verify is the assessor's. `ledger keygen` is the engineer's setup too: it makes the "
               "deployment's instance key, which signs root statements and is never the policy authority key. "
               "`authorize` splits the same way as `swap`: sign is the engineer's (it holds the authority key), "
               "verify is the assessor's.")
    return "\n".join(out)


def _package_version() -> str:
    from importlib import metadata
    try:
        return metadata.version('prismpath')
    except metadata.PackageNotFoundError:        # running from a source tree that was never installed
        return 'unknown (not installed)'


def build_parser() -> argparse.ArgumentParser:
    from prismpath.cli import agent, evidence, flows, policy, routing, runtime
    parser = argparse.ArgumentParser(prog='prismpath', description='Command-line interface for prismpath',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--version', action='version', version='prismpath ' + _package_version())
    subparsers = parser.add_subparsers(dest='command', metavar='<command>')

    flows.register(subparsers)
    routing.register(subparsers)
    policy.register(subparsers)
    runtime.register(subparsers)
    agent.register(subparsers)
    evidence.register(subparsers)

    parser.epilog = _grouped_help(subparsers)
    subparsers._choices_actions = []   # the flat list is replaced by the grouped epilog above
    return parser


def main(argv=None) -> int:
    words = sys.argv[1:] if argv is None else list(argv)
    if words[:2] == ['agent', 'hook'] and len(words) <= 3 and set(words[2:]) <= {'--json'}:
        # the hook is a new process per tool call: answer before the whole parser is built
        from prismpath.agent import commands
        return commands.hook_main()
    from prismpath import kinds_builtin
    kinds_builtin.load()                               # every built in target kind, before any command reads one
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 2
    try:
        return args.func(args)
    except Exception as exc:
        message = None if os.environ.get("PRISMPATH_DEBUG") else _user_error(exc)
        if message is None:
            raise
        print(f"prismpath {args.command}: {message}", file=sys.stderr)
        return exc.code if isinstance(exc, CliError) else 2
