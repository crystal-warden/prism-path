#!/usr/bin/env python3
"""Lynis scanner adapter — map Lynis audit report findings into posture facts.

Input: a parsed Lynis report as a dict of key -> value (Lynis writes key=value pairs to its
report.dat, for example pam_faillock_deny=5 and fips_mode_enabled=1).

Coverage is deliberately CONSERVATIVE and honest. A Lynis finding is mapped to a fact only where the
finding genuinely and specifically establishes that fact. A single hardening signal is never fanned
out across several distinct objectives (a two-factor flag is not treated as MFA for local, network,
and non-privileged access at once), unrelated concepts are never conflated (an SSH idle timeout is
not a screen lock), and a weaker signal is never promoted to a stronger claim (a firewall being active
is not a default-deny policy; an antivirus being installed is not enforced real-time scanning). Facts
Lynis does not truly report are left absent so the posture_connector defers those controls rather than
grading them from a proxy. Lynis therefore fully decides a handful of host controls and honestly
defers the rest (MFA, screen lock, password complexity, and others).
"""


def _as_bool(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return None
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "enabled"):
        return True
    if s in ("0", "false", "no", "off", "disabled", ""):
        return False
    return None


def _as_int(v):
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _first(raw, *keys):
    for k in keys:
        if raw.get(k) is not None:
            return raw[k]
    return None


def parse(raw):
    """Lynis parsed report (dict of key -> value) -> facts, mapping only what Lynis specifically reports."""
    raw = raw or {}
    facts = {}

    # 3.1.8 limit unsuccessful logon attempts: a configured PAM faillock/tally deny count
    lockout = _as_int(_first(raw, "pam_faillock_deny", "pam_tally2_deny", "account_lockout_threshold"))
    if lockout is not None:
        facts["account_lockout_threshold"] = lockout
        facts["account_lockout_enforced"] = lockout > 0

    # 3.5.8 prohibit password reuse: a configured remember/history count
    hist = _as_int(_first(raw, "pam_pwhistory_remember", "password_remember", "password_history_count"))
    if hist is not None:
        facts["password_history_count"] = hist
        facts["password_history_enforced"] = hist > 0

    # 3.13.11 FIPS-validated cryptography: OS FIPS mode
    fips = _as_bool(_first(raw, "fips_mode_enabled", "fips_mode", "fips_enabled"))
    if fips is not None:
        facts["fips_validated_cryptography"] = fips

    # 3.13.16 protect CUI at rest: full-disk encryption active
    enc = _as_bool(_first(raw, "disk_encryption_enabled", "luks_active"))
    if enc is not None:
        facts["encryption_at_rest_enforced"] = enc

    # 3.1.9 privacy and security notices: a login/legal banner is present
    banner = _as_bool(_first(raw, "login_banner_enabled", "legal_banner_present", "issue_net_banner_defined"))
    if banner is not None:
        facts["login_banner_defined"] = banner
        facts["login_banner_enforced"] = banner

    # 3.14.4 update malicious-code protection: the AV signature auto-update service
    av_update = _as_bool(_first(raw, "freshclam_active", "antivirus_auto_update_enabled"))
    if av_update is not None:
        facts["antivirus_auto_update_enabled"] = av_update

    # 3.13.6 deny by default, allow by exception: ONLY from the actual default-policy signal,
    # never from "a firewall is running"
    fw_deny = _as_bool(_first(raw, "firewall_default_policy_deny", "firewall_default_deny"))
    if fw_deny is not None:
        facts["default_deny_firewall_policy_enforced"] = fw_deny
    fw_exc = _as_bool(_first(raw, "firewall_allow_by_exception", "firewall_exception_rules_present"))
    if fw_exc is not None:
        facts["firewall_allow_by_exception_enforced"] = fw_exc

    return facts
