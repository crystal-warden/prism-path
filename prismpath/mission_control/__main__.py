# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""`python -m prismpath.mission_control [--read-only]` — the loopback command center.

The console binds loopback. MC_HOST naming any other address is refused unless MC_ALLOW_NON_LOOPBACK=1
is set as well, which prints a warning; even then the session guard serves only a loopback `Host`.
The launch writes this session's token to a file only its user can read, prints the URL without the
token (the page carries it) and removes the file when the console stops.
"""
import argparse
import ipaddress
import os
import signal
import sys

try:
    import uvicorn

    from . import core
    from . import session as session_module
    from .app import create_app
except ImportError as exc:
    from prismpath import extras
    missing = extras.from_exception(exc)
    if missing is None:
        raise
    sys.exit(f"prismpath mission_control: {missing.install}")

ALLOW_NON_LOOPBACK_ENV = "MC_ALLOW_NON_LOOPBACK"


def is_loopback(host: str) -> bool:
    if host.strip().lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip().strip("[]")).is_loopback
    except ValueError:
        return False


def check_bind_host(host: str, environ=None):
    """None for a loopback host. For any other host, exit unless MC_ALLOW_NON_LOOPBACK=1, and then
    return the warning to print."""
    environ = os.environ if environ is None else environ
    if is_loopback(host):
        return None
    if environ.get(ALLOW_NON_LOOPBACK_ENV) != "1":
        raise SystemExit(f"prismpath mission_control: refusing to bind {host!r}, which is not a loopback "
                         f"address. The console starts and stops sprints and edits flow files; set "
                         f"{ALLOW_NON_LOOPBACK_ENV}=1 as well to bind it anyway.")
    return (f"WARNING: binding {host!r}, which is not loopback, because {ALLOW_NON_LOOPBACK_ENV}=1. The "
            f"session guard still serves only a loopback Host header.")


def startup_lines(settings, session, token_path):
    """What the launch prints. The URL carries no token: the page served at it does."""
    log = core.audit.LOG
    return [
        f"mission control at http://127.0.0.1:{settings.port}/  ({'read-only' if settings.read_only else 'full'} "
        f"posture)  proj={settings.proj}  audit_root={log.current_root()[:16]}",
        f"session {session.fingerprint}: token in {token_path} (owner only), sent as {session_module.TOKEN_HEADER}",
        (f"audit log signed by instance key {log.instance_key.fingerprint}, statements in {log.statements_path}"
         if log.signing else
         "audit log not signed: no instance key (set PRISMPATH_INSTANCE_KEY to sign root statements)"),
    ]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="python -m prismpath.mission_control",
                                     description="The PrismPath Mission Control console, on loopback.")
    parser.add_argument("--read-only", action="store_true",
                        help="mount no route that controls a sprint or writes a file (also MC_READ_ONLY=1)")
    args = parser.parse_args(argv)
    settings = core.SETTINGS
    if args.read_only:
        settings.read_only = True
    warning = check_bind_host(settings.host)
    if warning:
        print(warning, file=sys.stderr, flush=True)
    session = session_module.Session.mint()
    application = create_app(read_only=settings.read_only, session=session)
    core.follow_active_sprint(core.STATE)                # the event stream keeps following from here
    token_path = session.write_token_file(settings.state_dir, settings.port)
    for line in startup_lines(settings, session, token_path):
        print(line, flush=True)
    def remove_token_file():
        try:
            if session_module.read_token_file(settings.state_dir, settings.port) == session.token:
                os.remove(token_path)
        except OSError:
            pass

    # uvicorn re-raises the signal that stopped it once it has shut down, under the handler that was
    # installed before it started, so the token file is removed from that handler as well as on return.
    def stop_on_signal(signum, _frame):
        remove_token_file()
        signal.signal(signum, signal.SIG_DFL)
        signal.raise_signal(signum)

    for stopping in (signal.SIGINT, signal.SIGTERM):
        signal.signal(stopping, stop_on_signal)
    try:
        uvicorn.run(application, host=settings.host, port=settings.port, log_level="warning")
    finally:
        remove_token_file()


if __name__ == "__main__":
    main()
