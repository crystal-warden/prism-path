#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# Phase 1 smoke: each installed comparator reports its version and answers one trivial
# decision. Nothing here touches the corpus; translators are Phase 2. Prints a block per system
# that TOOLCHAIN.md records verbatim. Servers run on loopback on non default ports and are
# killed on exit.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$HERE/../.toolchain/bin"
WORK="$(mktemp -d)"
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT
status=0
say() { printf '%s\n' "$*"; }

say "== opa"
if [ -x "$BIN/opa" ]; then
  "$BIN/opa" version | sed -n '1,2p;/Platform/p'
  cat > "$WORK/p.rego" <<'REGO'
package smoke
default decision := "deny"
decision := "allow" if { input.port == 443 }
REGO
  say "eval port=443 -> $("$BIN/opa" eval -f raw -d "$WORK/p.rego" -i <(echo '{"port":443}') 'data.smoke.decision')"
  say "eval port=23  -> $("$BIN/opa" eval -f raw -d "$WORK/p.rego" -i <(echo '{"port":23}') 'data.smoke.decision')"
else say "MISSING"; status=1; fi

say "== cedar"
if [ -x "$BIN/cedar" ]; then
  "$BIN/cedar" --version
  cat > "$WORK/p.cedar" <<'CEDAR'
permit(principal, action == Action::"connect", resource) when { context.port == 443 };
CEDAR
  echo '[]' > "$WORK/entities.json"
  echo '{"port":443}' > "$WORK/c443.json"; echo '{"port":23}' > "$WORK/c23.json"
  cz() { "$BIN/cedar" authorize --policies "$WORK/p.cedar" --entities "$WORK/entities.json" --principal 'User::"a"' --action 'Action::"connect"' --resource 'Host::"h"' --context "$1" 2>&1 | grep -v '^$' | head -1; }
  say "authorize port=443 -> $(cz "$WORK/c443.json") (exit 0 = ALLOW, exit 2 = DENY)"
  say "authorize port=23  -> $(cz "$WORK/c23.json")"
else say "MISSING (cargo install may still be running)"; status=1; fi

say "== cerbos"
if [ -x "$BIN/cerbos" ]; then
  "$BIN/cerbos" --version 2>&1 | head -2
  mkdir -p "$WORK/cerbos/policies"
  cat > "$WORK/cerbos/policies/host.yaml" <<'YAML'
apiVersion: api.cerbos.dev/v1
resourcePolicy:
  version: default
  resource: host
  rules:
    - actions: ["connect"]
      effect: EFFECT_ALLOW
      roles: ["*"]
      condition:
        match:
          expr: request.resource.attr.port == 443
YAML
  cat > "$WORK/cerbos/conf.yaml" <<'YAML'
server:
  httpListenAddr: "127.0.0.1:3592"
  grpcListenAddr: "127.0.0.1:3593"
storage:
  driver: disk
  disk:
    directory: POLICYDIR
YAML
  sed -i "s|POLICYDIR|$WORK/cerbos/policies|" "$WORK/cerbos/conf.yaml"
  "$BIN/cerbos" server --config="$WORK/cerbos/conf.yaml" >"$WORK/cerbos.log" 2>&1 &
  for _ in $(seq 1 40); do curl -sf http://127.0.0.1:3592/_cerbos/health >/dev/null 2>&1 && break; sleep 0.25; done
  say "health -> $(curl -s http://127.0.0.1:3592/_cerbos/health)"
  req() { curl -s -X POST http://127.0.0.1:3592/api/check/resources -H 'content-type: application/json' -d "{\"requestId\":\"s\",\"principal\":{\"id\":\"a\",\"roles\":[\"user\"]},\"resources\":[{\"actions\":[\"connect\"],\"resource\":{\"kind\":\"host\",\"id\":\"h\",\"attr\":{\"port\":$1}}}]}" | jq -r '.results[0].actions.connect'; }
  say "check port=443 -> $(req 443)"
  say "check port=23  -> $(req 23)"
  kill %1 2>/dev/null; wait 2>/dev/null
else say "MISSING"; status=1; fi

say "== openfga"
if [ -x "$BIN/openfga" ]; then
  "$BIN/openfga" version 2>&1 | head -1
  "$BIN/openfga" run --datastore-engine memory --http-addr 127.0.0.1:8090 --grpc-addr 127.0.0.1:8091 --playground-enabled=false --log-format json >"$WORK/fga.log" 2>&1 &
  for _ in $(seq 1 40); do curl -sf http://127.0.0.1:8090/healthz >/dev/null 2>&1 && break; sleep 0.25; done
  say "health -> $(curl -s http://127.0.0.1:8090/healthz)"
  STORE=$(curl -s -X POST http://127.0.0.1:8090/stores -H 'content-type: application/json' -d '{"name":"smoke"}' | jq -r .id)
  MODEL=$(curl -s -X POST "http://127.0.0.1:8090/stores/$STORE/authorization-models" -H 'content-type: application/json' -d '{"schema_version":"1.1","type_definitions":[{"type":"user"},{"type":"doc","relations":{"viewer":{"this":{}}},"metadata":{"relations":{"viewer":{"directly_related_user_types":[{"type":"user"}]}}}}]}' | jq -r .authorization_model_id)
  curl -s -X POST "http://127.0.0.1:8090/stores/$STORE/write" -H 'content-type: application/json' -d '{"writes":{"tuple_keys":[{"user":"user:bob","relation":"viewer","object":"doc:d2"}]}}' >/dev/null
  chk() { curl -s -X POST "http://127.0.0.1:8090/stores/$STORE/check" -H 'content-type: application/json' -d "{\"authorization_model_id\":\"$MODEL\",\"tuple_key\":{\"user\":\"user:$1\",\"relation\":\"viewer\",\"object\":\"doc:d2\"}}" | jq -r .allowed; }
  say "check bob viewer doc:d2   -> $(chk bob)"
  say "check alice viewer doc:d2 -> $(chk alice)"
  kill %1 2>/dev/null; wait 2>/dev/null
else say "MISSING"; status=1; fi
exit $status
