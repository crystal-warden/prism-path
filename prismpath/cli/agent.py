# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Governed Claude Code session (`prismpath agent`) commands."""
import argparse
import os

from prismpath.cli.common import CliError


def register(subparsers) -> None:
    agent_parser = subparsers.add_parser(
        'agent', help='Govern a Claude Code session: keys and the signed default policy (init), the PreToolUse '
                      'hook (hook), the sealed and verified runs of receipts (verify), what is set up (status), the rules with their hits and outcomes (rules), approved asks to consider signing (approvals)')
    agent_sub = agent_parser.add_subparsers(dest='agent_action', metavar='<action>', required=True)
    agent_init = agent_sub.add_parser(
        'init', help='make the authority and instance keys in the user config directory, record the signed '
                     'agent_default policy, and write the hook entries into the project\'s .claude/settings.json '
                     '(shown first; written with --yes or a y at the prompt)')
    agent_init.add_argument('--project', default=None,
                            help='the project directory (default $CLAUDE_PROJECT_DIR, else the current directory)')
    agent_init.add_argument('--yes', action='store_true', help='write the settings change without asking')
    agent_init.add_argument('--follow', default=None, metavar='STREAM',
                            help='follow a policy stream instead: the home holds no authority key, takes the trust '
                                 'anchor given with --anchor, shows its fingerprint, and after --confirm commits the '
                                 'releases the controller offers (`prismpath dist`)')
    agent_init.add_argument('--anchor', default=None, metavar='FILE', help='with --follow: the stream\'s trust anchor')
    agent_init.add_argument('--confirm', default=None, metavar='FINGERPRINT',
                            help='with --follow: the anchor\'s fingerprint, as the owner gave it')
    agent_init.add_argument('--policy', default=None, metavar='STARTER|FILE',
                            help='the policy to record. A starter is strict (refuses what it cannot read and shell '
                                 'commands that change files), default (asks about those), review (also asks about '
                                 'every change inside the project) or session (default, and also asks about later calls '
                                 'when the session already changed protected code or ran many shell commands). A FILE '
                                 'is your own rules source (.rules.md) or image (.core.json), compiled and checked as '
                                 '`prismpath policy compile --target agent` checks it (default: the one recorded, else '
                                 'default)')
    agent_hook = agent_sub.add_parser(
        'hook', help='what Claude Code runs: the hook JSON on stdin, the answer on stdout; any failure is a deny '
                     'with cause agent:hook-error, never an allow')
    agent_verify = agent_sub.add_parser(
        'verify', help='seal the open runs and verify every run with both keys pinned, every receipt replayed '
                       'through the reference kernel')
    agent_verify.add_argument('--tamper-demo', dest='tamper_demo', action='store_true',
                              help='also copy a run to a temporary directory, flip one byte, show the verify '
                                   'refuse it, and delete the copy')
    agent_status = agent_sub.add_parser(
        'status', help='the keys and their ids, the policy hash, the project\'s hook entries and every run with '
                       'its receipt count, open or sealed')
    agent_status.add_argument('--project', default=None,
                              help='the project whose .claude/settings.json is read (default as for init)')
    agent_rules = agent_sub.add_parser(
        'rules', help='the installed policy\'s rules in order, each with its hits and last hit counted from the '
                      'receipts that verify, the core\'s own refusals, the rules never matched and the rules no '
                      'reading can reach; it changes nothing')
    agent_rules.add_argument('--since', default=None, metavar='ISO_TIME',
                             help='count only runs whose time is at or after this ISO 8601 time')
    agent_approvals = agent_sub.add_parser(
        'approvals', help='the escalate rules whose asks were approved (and the call ran) at least N times, with counts '
                          'and example readings as classes only: candidates for the owner to sign into the policy; '
                          'it changes nothing and adopts nothing')
    agent_approvals.add_argument('--min', type=int, default=3, metavar='N',
                                 help='list a rule approved at least this many times (default 3)')
    agent_approvals.add_argument('--since', default=None, metavar='ISO_TIME',
                                 help='count only runs whose time is at or after this ISO 8601 time')
    agent_doctor = agent_sub.add_parser(
        'doctor', help='check the whole setup (key modes and pairs, the policy, the hook entries and their '
                       'interpreter, a timed dry run, the runs, free disk) and print ok, warn or fail with the '
                       'fixing command for each; it changes nothing')
    agent_doctor.add_argument('--project', default=None,
                              help='the project whose .claude/settings.json is checked (default as for init)')
    agent_zones = agent_sub.add_parser(
        'zones', help='the owner\'s protected code: `set` records and signs a zone file (the protected names, bound to '
                      'the recorded policy and the project), `status` says what the hook will do about zones, `warm` '
                      'asks Context Cloud about every file so the hook answers from the cache')
    agent_zones.add_argument('zones_action', choices=('set', 'status', 'warm'))
    agent_zones.add_argument('--project', default=None,
                             help='the project the zones are for (default as for init)')
    agent_zones.add_argument('--protected', action='append', default=None, metavar='NAME',
                             help='set: a protected function, class or module by its dotted name, as Context Cloud '
                                  'spells it (repeat, or comma separate)')
    agent_zones.add_argument('--protected-file', default=None, metavar='FILE',
                             help='set: a file with one protected name per line')
    agent_zones.add_argument('--index', default=None, metavar='FILE',
                             help='set: the Context Cloud index (default .contextcloud/index.sqlite in the project)')
    for sub in (agent_init, agent_hook, agent_verify, agent_status, agent_doctor, agent_rules, agent_approvals, agent_zones):
        sub.add_argument('--json', action='store_true', help='machine readable output')
    agent_run = agent_sub.add_parser(
        'run', help='run a program as the agent under the sandbox (Linux, bubblewrap and socat): the workspace is '
                    'the only writable path, its control paths and the staged settings are read only, and the '
                    'only way out is a proxy that allows the model API. A "yes, and don\'t ask again" that '
                    'Claude Code would save to .claude/settings.local.json fails here, by design')
    agent_run.add_argument('--workspace', default=None, help='the directory the agent may write (default: the current directory)')
    agent_run.add_argument('--credential', default=None, metavar='FILE',
                           help='copy this one file into the sandbox as its Claude credential (off unless given; '
                                'PrismPath never looks for a login of its own)')
    agent_run.add_argument('--egress-log', default=None, metavar='FILE',
                           help='keep the proxy\'s log of every connection attempt here (default: in the run directory of the egress run, beside its receipts)')
    agent_run.add_argument('--max-processes', type=int, default=None, help='the process limit inside the sandbox')
    agent_run.add_argument('--allow-host', action='append', default=None, metavar='HOST',
                           help='a host name the policy may allow on port 443 (net_dest allowed_host); repeatable. The digest of the sorted list is recorded with the run')
    agent_run.add_argument('--local-model', default=None, metavar='http://HOST:PORT',
                           help='a fixed route to one local model server: the sandbox reaches only that host and port, '
                                'at 127.0.0.1:PORT inside, and each use is logged (a separate route, not a proxy exception)')
    agent_run.add_argument('--ro', action='append', default=None, metavar='PATH',
                           help='also show this host path to the program, read only (repeatable)')
    agent_run.add_argument('program', nargs=argparse.REMAINDER, help='-- PROGRAM [ARGS]')
    agent_parser.set_defaults(func=agent_cmd)


def agent_cmd(args) -> int:
    from prismpath.agent import commands
    if args.agent_action == 'hook':
        return commands.hook_main()
    project = args.project if getattr(args, 'project', None) else (os.environ.get('CLAUDE_PROJECT_DIR') or os.getcwd())
    try:
        if args.agent_action == 'run':
            return commands.run(args.program, args.workspace, args.credential, args.egress_log, args.max_processes,
                                args.local_model, args.ro, args.allow_host)
        if args.agent_action == 'init' and args.follow:
            return commands.follow(project, args.follow, args.anchor, args.confirm, args.yes, args.json)
        if args.agent_action == 'init':
            return commands.init(project, args.yes, args.json, policy=args.policy)
        if args.agent_action == 'verify':
            return commands.verify(args.json, args.tamper_demo)
        if args.agent_action == 'rules':
            from prismpath.agent import rules as agent_rules_report
            try:
                return agent_rules_report.rules(args.since, args.json)
            except agent_rules_report.RulesError as exc:
                raise CliError(str(exc))
        if args.agent_action == 'zones':
            return commands.zones_cmd(args.zones_action, project, args.protected, args.protected_file, args.index,
                                      args.json)
        if args.agent_action == 'approvals':
            from prismpath.agent import rules as agent_rules_report
            try:
                return agent_rules_report.approvals_command(args.since, args.min, args.json)
            except agent_rules_report.RulesError as exc:
                raise CliError(str(exc))
        if args.agent_action == 'doctor':
            from prismpath.agent import doctor
            return doctor.doctor(project, args.json)
        return commands.status(project, args.json)
    except commands.AgentError as exc:
        raise CliError(str(exc))
