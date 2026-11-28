# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The signer daemon: the instance key in its own process, behind a peer credential check.

Pinned here: a chain signed through the daemon is byte for byte the chain the key file signs and verifies pinned; the
daemon signs only root statements and run roots under its own key; a log whose tail and statements were deleted
cannot get a shorter chain signed (truncation), nor a fork at the same leaves, nor a skipped seq; the chain resumes
after a daemon restart and after a caller crashed between the signature and the write; a daemon that lost its state
refuses to start; a caller with no_new_privs, or under another user, is refused; the socket is mode 0600; and
PRISMPATH_INSTANCE_KEY=unix:PATH names the daemon."""
import hashlib
import json
import os
import stat
import subprocess
import sys
import threading

import pytest

pytest.importorskip("cryptography")

if not sys.platform.startswith("linux"):
    pytest.skip("the signer daemon is Linux only", allow_module_level=True)

import prismpath  # noqa: E402
from prismpath import canon  # noqa: E402
from prismpath.ledgers import audit_log, core_evidence, root_statement as rs, signer_daemon as sd  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(prismpath.__file__)))


def _confined_now() -> bool:
    seen = sd.confinement(os.getpid())
    return seen["no_new_privs"] or seen["seccomp"] != 0


def _leaves(n):
    return [hashlib.sha256(b"receipt %d" % i).hexdigest() for i in range(n)]


class Running:
    def __init__(self, tmp_path, fresh=True, **kwargs):
        self.tmp = tmp_path
        keys = tmp_path / "keys"
        if not (keys / "instance.key").exists():
            rs.keygen(str(keys), "instance")
        self.key_path = str(keys / "instance.key")
        self.pub = (keys / "instance.pub").read_bytes()
        self.socket = str(tmp_path / "run" / "signer.sock")
        self.state = str(tmp_path / "signer.state")
        self.daemon = sd.SignerDaemon(rs.InstanceKey.load(self.key_path), self.socket, self.state, fresh=fresh,
                                      **kwargs)
        self.daemon.bind()
        self.thread = threading.Thread(target=self.daemon.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        self.daemon.stop()
        self.thread.join(5)


@pytest.fixture
def running(tmp_path):
    if _confined_now():
        pytest.skip("this test process is itself confined, so the daemon would refuse it")
    one = Running(tmp_path)
    yield one
    one.stop()


def _chain(signer, sizes, leaves):
    return [signer.sign(rs.merkle_root(leaves[:n]), n, "test") for n in sizes]


def test_a_chain_signed_through_the_daemon_is_the_chain_the_key_file_signs(running, tmp_path, monkeypatch):
    key = sd.DaemonKey(running.socket)
    assert key.public_raw == running.pub and key.key_id == rs.key_id_of(running.pub)
    leaves = _leaves(9)
    path = str(tmp_path / "a.roots.jsonl")
    clock = iter(range(100, 200))
    monkeypatch.setattr(rs, "_now_us", lambda: next(clock))
    _chain(rs.RootSigner(key, path, rs.LOG_AUDIT), (2, 6, 9), leaves)
    statements, findings = rs.read_statements(path)
    report = rs.verify_chain(statements, findings, lambda n: rs.merkle_root(leaves[:n]), 9, pinned=[running.pub])
    assert report["status"] == rs.SIGNED and report["statements"] == 3
    clock = iter(range(100, 200))
    direct = str(tmp_path / "b.roots.jsonl")
    _chain(rs.RootSigner(rs.InstanceKey.load(running.key_path), direct, rs.LOG_AUDIT), (2, 6, 9), leaves)
    assert open(path, "rb").read() == open(direct, "rb").read()


def test_it_signs_only_root_statements_and_run_roots(running):
    key = sd.DaemonKey(running.socket)
    for message in (b"anything", b"prismpath.core-image/1\x00policy", canon.CANON2_DOMAIN + b'{"a":1}',
                    rs.SIGNING_DOMAIN + b"not json", rs.SIGNING_DOMAIN + b'{"format":"x"}'):
        with pytest.raises(sd.SignerRefused):
            key.sign(message)
    statement = core_evidence.make_root_statement(key, rs.merkle_root(_leaves(3)), 3, b"{}", time_us=1)
    direct = core_evidence.make_root_statement(rs.InstanceKey.load(running.key_path), rs.merkle_root(_leaves(3)), 3,
                                               b"{}", time_us=1)
    assert statement == direct


def test_it_refuses_a_body_under_another_key(running, tmp_path):
    other = rs.keygen(str(tmp_path / "other"), "instance")
    forged = rs.make_statement(rs.InstanceKey.load(other["private"]), log="audit-log", seq=0, root="", leaves=0,
                               prev="", trigger="t")
    with pytest.raises(sd.SignerRefused) as err:
        sd.DaemonKey(running.socket).sign(rs.signed_bytes(forged))
    assert err.value.reason == "other_key"


def test_a_truncated_log_cannot_get_a_shorter_chain_signed(running, tmp_path):
    """The tail of the statements file is deleted, as a worker that wants a shorter story would: the next statement
    the signer is asked for repeats a seq already signed, and covering fewer leaves is refused outright."""
    key = sd.DaemonKey(running.socket)
    path = tmp_path / "a.roots.jsonl"
    leaves = _leaves(8)
    _chain(rs.RootSigner(key, str(path), rs.LOG_AUDIT), (3, 8), leaves)
    lines = path.read_text().splitlines(keepends=True)
    path.write_text(lines[0])
    resumed = rs.RootSigner.__new__(rs.RootSigner)          # a caller that skips the resume from the daemon
    resumed.key, resumed.path, resumed.log, resumed._seq = key, str(path), rs.LOG_AUDIT, 1
    resumed._prev = rs.statement_hash(rs.read_statements(str(path))[0][0])
    with pytest.raises(sd.SignerRefused) as err:
        resumed.sign(rs.merkle_root(leaves[:5]), 5, "test")
    assert err.value.reason == "truncated"
    with pytest.raises(sd.SignerRefused) as err:
        resumed.sign(rs.merkle_root(leaves), 8, "test")
    assert err.value.reason == "chain_broken"
    assert running.daemon.heads["audit-log"]["leaves"] == 8


def test_a_fork_and_a_skipped_seq_are_refused(running, tmp_path):
    key = sd.DaemonKey(running.socket)
    leaves = _leaves(6)
    first = _chain(rs.RootSigner(key, str(tmp_path / "a.roots.jsonl"), rs.LOG_AUDIT), (4,), leaves)[0]
    fork = {k: v for k, v in rs.make_statement(rs.InstanceKey.load(running.key_path), log="audit-log", seq=1,
                                               root=rs.merkle_root(_leaves(5)[1:]), leaves=4,
                                               prev=rs.statement_hash(first), trigger="t").items()}
    with pytest.raises(sd.SignerRefused) as err:
        key.sign(rs.signed_bytes(fork))
    assert err.value.reason == "fork"
    skip = rs.make_statement(rs.InstanceKey.load(running.key_path), log="audit-log", seq=3, root=rs.merkle_root(leaves),
                             leaves=6, prev=rs.statement_hash(first), trigger="t")
    with pytest.raises(sd.SignerRefused) as err:
        key.sign(rs.signed_bytes(skip))
    assert err.value.reason == "chain_broken"


def test_the_chain_resumes_after_a_daemon_restart(tmp_path):
    if _confined_now():
        pytest.skip("this test process is itself confined")
    one = Running(tmp_path)
    path = str(tmp_path / "a.roots.jsonl")
    leaves = _leaves(7)
    _chain(rs.RootSigner(sd.DaemonKey(one.socket), path, rs.LOG_AUDIT), (2, 4), leaves)
    one.stop()
    again = Running(tmp_path, fresh=False)
    try:
        _chain(rs.RootSigner(sd.DaemonKey(again.socket), path, rs.LOG_AUDIT), (7,), leaves)
    finally:
        again.stop()
    statements, findings = rs.read_statements(path)
    report = rs.verify_chain(statements, findings, lambda n: rs.merkle_root(leaves[:n]), 7, pinned=[again.pub])
    assert report["status"] == rs.SIGNED and [s["seq"] for s in statements] == [0, 1, 2]


def test_the_chain_resumes_after_the_caller_crashed_before_writing(running, tmp_path):
    """The daemon signed statement 1 and wrote its state, and the caller died before the line reached the file. The
    next RootSigner on the file appends the statement the daemon holds, so the chain has no gap and verifies."""
    key = sd.DaemonKey(running.socket)
    path = str(tmp_path / "a.roots.jsonl")
    leaves = _leaves(6)
    first = _chain(rs.RootSigner(key, path, rs.LOG_AUDIT), (2,), leaves)[0]
    lost = rs.make_statement(key, log="audit-log", seq=1, root=rs.merkle_root(leaves[:4]), leaves=4,
                             prev=rs.statement_hash(first), trigger="test")          # signed, never written
    signer = rs.RootSigner(key, path, rs.LOG_AUDIT)
    signer.sign(rs.merkle_root(leaves), 6, "test")
    statements, findings = rs.read_statements(path)
    assert statements[1] == lost
    report = rs.verify_chain(statements, findings, lambda n: rs.merkle_root(leaves[:n]), 6, pinned=[running.pub])
    assert report["status"] == rs.SIGNED


def test_a_daemon_that_lost_its_state_refuses_to_start(tmp_path):
    rs.keygen(str(tmp_path / "keys"), "instance")
    key = rs.InstanceKey.load(str(tmp_path / "keys" / "instance.key"))
    with pytest.raises(RuntimeError):
        sd.SignerDaemon(key, str(tmp_path / "s.sock"), str(tmp_path / "missing.state"))
    other = rs.keygen(str(tmp_path / "other"), "instance")
    sd.SignerDaemon(key, str(tmp_path / "s.sock"), str(tmp_path / "ok.state"), fresh=True)
    with pytest.raises(RuntimeError):
        sd.SignerDaemon(rs.InstanceKey.load(other["private"]), str(tmp_path / "s.sock"), str(tmp_path / "ok.state"))


def test_the_socket_is_private(running):
    assert stat.S_IMODE(os.stat(running.socket).st_mode) == 0o600


def test_a_caller_of_another_user_is_refused(tmp_path):
    if _confined_now():
        pytest.skip("this test process is itself confined")
    one = Running(tmp_path, allowed_uids=[os.getuid() + 1])
    try:
        with pytest.raises(sd.SignerRefused) as err:
            sd.DaemonKey(one.socket)
        assert err.value.reason == "uid_not_allowed"
    finally:
        one.stop()


def test_a_confined_caller_is_refused(running):
    """A process that set no_new_privs, as every worker PrismPath confines has, asks for the public key and a
    signature, and is refused both; the daemon records who asked."""
    script = ("import ctypes, sys\n"
              "libc = ctypes.CDLL(None, use_errno=True)\n"
              "assert libc.prctl(38, 1, 0, 0, 0) == 0\n"
              "from prismpath.ledgers import signer_daemon as sd\n"
              "try:\n"
              "    sd.DaemonKey(sys.argv[1])\n"
              "except sd.SignerRefused as err:\n"
              "    print(err.reason)\n")
    env = {**os.environ, "PYTHONPATH": REPO_ROOT + os.pathsep + os.environ.get("PYTHONPATH", "")}
    done = subprocess.run([sys.executable, "-c", script, running.socket], capture_output=True, text=True, env=env,
                          timeout=60)
    assert done.stdout.strip() == "confined_caller", done.stderr
    assert running.daemon.refusals[-1]["reason"] == "confined_caller"


def test_confinement_reads_the_status_file(tmp_path):
    (tmp_path / "7").mkdir()
    (tmp_path / "7" / "status").write_text("Name:\tx\nNoNewPrivs:\t0\nSeccomp:\t2\n")
    assert sd.confinement(7, str(tmp_path)) == {"readable": True, "no_new_privs": False, "seccomp": 2}
    assert sd.confinement(8, str(tmp_path))["no_new_privs"] is True        # unreadable counts as confined


def test_the_environment_names_the_daemon(running, tmp_path):
    key = rs.key_from_env({rs.INSTANCE_KEY_ENV: "unix:" + running.socket})
    assert isinstance(key, sd.DaemonKey) and key.public_raw == running.pub
    log = audit_log.AuditLog(str(tmp_path / "run.audit.jsonl"), instance_key=key, sign_appends=True)
    log.append("tester", "test", {"n": 1})
    statements, _ = rs.read_statements(rs.statements_path_for(str(tmp_path / "run.audit.jsonl")))
    assert statements and statements[-1]["key_id"] == key.key_id


def test_a_deleted_last_statement_is_restored_from_the_daemon(running, tmp_path):
    key = sd.DaemonKey(running.socket)
    path = tmp_path / "a.roots.jsonl"
    leaves = _leaves(5)
    _chain(rs.RootSigner(key, str(path), rs.LOG_AUDIT), (2, 5), leaves)
    whole = path.read_bytes()
    path.write_text(path.read_text().splitlines(keepends=True)[0])
    rs.RootSigner(key, str(path), rs.LOG_AUDIT)
    assert path.read_bytes() == whole


def test_load_signer_names_the_daemon_behind_the_port(running):
    from prismpath.onion import keys
    key = keys.load_signer("unix:" + running.socket)
    assert isinstance(key, sd.DaemonKey) and isinstance(key, keys.ChainSigner)
    assert key.public_raw == running.pub and key.fingerprint == keys.fingerprint(keys.key_id_of(running.pub))
    message = rs.SIGNING_DOMAIN + b"not a statement"
    with pytest.raises(sd.SignerRefused):
        key.sign(message)                       # the daemon signs statements only, so the port holds its refusal
    root = rs.merkle_root(_leaves(2))
    assert core_evidence.make_root_statement(key, root, 2, b"{}", time_us=1) == \
        core_evidence.make_root_statement(keys.load_signer(running.key_path), root, 2, b"{}", time_us=1)
