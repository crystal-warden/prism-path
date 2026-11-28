# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""Shared CLI error, validation, and reporting helpers."""
import json
import os


class CliError(Exception):
    """A failure the person at the terminal can fix (a missing program, a flow that cannot run, a
    directory that is not a git repository). `main` prints the message as one line on stderr and
    exits with `code`, which is 2 like every other input or environment refusal here."""

    def __init__(self, message: str, code: int = 2):
        super().__init__(message)
        self.code = code


# The ordinary mistakes `main` reports in one line. Anything else is a bug and keeps its traceback;
# PRISMPATH_DEBUG=1 shows the traceback for these too.
_FILE_ERRORS = (FileNotFoundError, NotADirectoryError, IsADirectoryError, PermissionError)


def user_error(exc: BaseException):
    """The one line `main` prints for `exc`, or None when `exc` is not an ordinary user mistake."""
    from prismpath import extras
    from prismpath.kernel.parser import FlowInputError, ParseError
    if isinstance(exc, (CliError, FlowInputError)):
        return str(exc)
    missing = extras.from_exception(exc)
    if missing is not None:
        return missing.install
    if isinstance(exc, _FILE_ERRORS):
        if exc.filename is not None:
            return f"{exc.filename}: {exc.strerror}"
        return str(exc)
    if isinstance(exc, ParseError):
        return f"the flow document cannot be parsed: {exc}"
    if isinstance(exc, UnicodeDecodeError):
        return f"an input file is not UTF-8 text ({exc.reason} at byte {exc.start})"
    if isinstance(exc, json.JSONDecodeError):
        return f"an input file is not valid JSON: {exc}"
    from prismpath.workers.chat_agent import ChatAgentError
    if isinstance(exc, ChatAgentError):
        return f"the worker did not answer: {exc}"
    from prismpath.evals.annotate import AnnotateError
    if isinstance(exc, AnnotateError):
        return str(exc)
    return None


def require_file(path: str) -> None:
    """Refuse a missing input file that the command would otherwise read as empty."""
    if not os.path.exists(path):
        import errno
        raise FileNotFoundError(errno.ENOENT, os.strerror(errno.ENOENT), path)


def require_program(program: str, how: str, action: str = "") -> None:
    """Refuse before shelling out to an external program that is not on PATH, naming it and how to
    get it, instead of letting the subprocess fail as a missing file. `action` names the subcommand
    action that needs it, after the `prismpath <command>:` prefix `main` prints."""
    import shutil
    if shutil.which(program) is None:
        raise CliError(f"{action + ' ' if action else ''}needs the `{program}` program on PATH ({how})")


def cause_code(reason: str):
    """The registry code of a refusal string; a parameterized one carries a `:<detail>` past the name."""
    from prismpath.kernel import causes
    return causes.code(causes.reason_name(reason))


def named_causes(reasons) -> str:
    return ", ".join(f"{reason} (cause {cause_code(reason)})" for reason in reasons)


def report_findings(findings, as_json: bool) -> int:
    """Print findings and return an exit code (non-zero iff any error-severity finding)."""
    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding for finding in findings if finding.severity == "warning"]
    if as_json:
        print(json.dumps({
            "ok": not errors,
            "errors": len(errors), "warnings": len(warnings),
            "findings": [finding.as_dict() for finding in findings],
        }, indent=2))
        return 1 if errors else 0
    for finding in findings:
        print(finding)
    if not findings:
        print("  clean ✅  · the flow compiles")
    else:
        summary = []
        if errors:
            summary.append(f"{len(errors)} error(s)")
        if warnings:
            summary.append(f"{len(warnings)} warning(s)")
        print(f"\n{'✗ does not compile' if errors else '✅ compiles (with advisories)'}"
              f" - {', '.join(summary)}")
    return 1 if errors else 0


def parse_flow(path: str):
    """Parse a flow file through `prismpath.cli.parse_file` so tests patching it keep working."""
    from prismpath import cli
    return cli.parse_file(path)
