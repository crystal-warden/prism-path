# Out-of-band timers: Flow-Ledger anchoring + SOC triage

## SOC triage poller (`cw-triage`)

`cw-triage.service` + `cw-triage.timer` run one triage cycle every 5 minutes against the SIEM
selected by `SIEM_KIND` (wazuh | elastic | ndjson | splunk; see `adapters/soc/siem.py`).
Edit the `Environment=` lines in the service (SIEM endpoint/credentials, `SOC_STATE_DIR`, the
LLM endpoint) before enabling; TLS verification to the indexer is **on by default**;
`SIEM_CA_CERT` for a private CA, `SIEM_VERIFY_TLS=0` only for self-signed lab boxes. Install
as user units exactly like the ledger timers below. With `SPRINT_LEDGER=1` each handled alert
becomes a git proof-commit and the poller resumes from the ledger.

# Flow-Ledger anchoring timers (out-of-band, #53)

Two `oneshot` services + timers that run the Flow-Ledger attestation on a schedule,
**outside** the pure PrismPath engine (SPEC §3.2; the engine never does network I/O):

| Unit | Cadence | Action |
|------|---------|--------|
| `cw-ledger-anchor` | hourly | `ledger anchor`: Merkle-root the new `PrismPath-Output-Hash` set + `ots stamp` the root (pending calendar proof) |
| `cw-ledger-upgrade` | daily | `ledger upgrade`: promote pending proofs to full Bitcoin attestation once confirmed (~1 to 6 h lag, SPEC C2) |

Both call `cw-ledger-run.sh`, which sources the project env (numpy/requests/`ots` on PATH)
and invokes `python3 -m prismpath.cli ledger …`, so the units stay interpreter-agnostic.

## STAGED · NOT ENABLED
These are templates. They are **not installed or enabled** on this node: there is no live
ledger producing `Output-Hash` data yet, and enabling a network-touching timer before there is
work to do would be noise. Deploy them when a ledger repo goes live.

## Deploy (when a ledger exists)
1. Edit `--repo` / `--out` / `--label` in `cw-ledger-anchor.service` and `cw-ledger-upgrade.service`
   to point at your ledger git repo and proof-store dir.
2. Install as **user** units (no root needed; matches the out-of-band, least-privilege posture):
   ```
   mkdir -p ~/.config/systemd/user
   cp cw-ledger-*.{service,timer} ~/.config/systemd/user/
   chmod +x cw-ledger-run.sh
   systemctl --user daemon-reload
   systemctl --user enable --now cw-ledger-anchor.timer cw-ledger-upgrade.timer
   loginctl enable-linger "$USER"   # so timers run without an active login session
   ```
3. Verify: `systemctl --user list-timers 'cw-ledger-*'`

## Air-gapped sites
Do **not** enable these (no egress). Use the air gap tier instead (`ledger_airgap.py`):
`export-request` in-enclave → carry the tiny hash-only bundle out → `relay-stamp` on a connected
relay → carry `.ots` proofs back → `import-proofs`; or the fully-offline RFC-3161 tier
(`ledger rfc3161`) against an internal TSA appliance. See SPEC §4.
