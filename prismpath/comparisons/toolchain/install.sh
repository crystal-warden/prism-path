#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
#
# Phase 1 of the layer comparison (prismpath/comparisons/PREREGISTRATION.md section 10):
# install the four comparators at PINNED versions into a gitignored toolchain directory,
# verifying every downloaded artifact against the checksum its project published.
#
# Pins (recorded 2026-09-08, the latest stable release of each on that day):
#   OPA      v1.20.2   static linux binary, sha256 from opa_linux_arm64_static.sha256
#   Cerbos   v0.55.0   linux tarball, sha256 from the release checksums.txt
#   OpenFGA  v1.19.0   linux tarball, sha256 from the release checksums.txt
#   Cedar    cedar-policy-cli 4.12.0 from crates.io, built with --locked by the local cargo
# Openlane is graded from its documentation and API surface only; nothing is installed for it.
#
# Usage: bash prismpath/comparisons/toolchain/install.sh [--skip-cedar]
# Idempotent: an artifact already present with the right checksum is not re downloaded.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/../.toolchain"
BIN="$ROOT/bin"
DL="$ROOT/dl"
mkdir -p "$BIN" "$DL"

ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) OPA_ARCH=arm64; CERBOS_ARCH=arm64; FGA_ARCH=arm64 ;;
  x86_64|amd64)  OPA_ARCH=amd64; CERBOS_ARCH=x86_64; FGA_ARCH=amd64 ;;
  *) echo "unsupported arch $ARCH" >&2; exit 1 ;;
esac
if [ "$ARCH" != "aarch64" ]; then
  echo "NOTE: checksums below are pinned for the aarch64 (arm64) artifacts the study ran on;" >&2
  echo "      on $ARCH the published checksum files are fetched and used instead." >&2
fi

OPA_VERSION=v1.20.2
OPA_SHA_ARM64=431bed5a365578241ab06c7cc1c7d0cdff8c11dcbc6f12c3488590deb8b8d66d
CERBOS_VERSION=0.55.0
CERBOS_SHA_ARM64=838c9d1339a69e078fccb1f30e5bfd85662c3b3b6d42a142c336bb34d1e5e3a3
CERBOSCTL_SHA_ARM64=4544d02d20e01fb9a915ce62f7b46f4243adea6dd5236095ce79411c9f139ef0
FGA_VERSION=1.19.0
FGA_SHA_ARM64=067e09ef5f1894e4f292bcc265da0063e7d6d763f2eb53cdebc8c3337adf0f64
CEDAR_CLI_VERSION=4.12.0

fetch() {  # fetch <url> <dest> <expected_sha256 or "">
  local url="$1" dest="$2" want="$3"
  if [ -f "$dest" ] && [ -n "$want" ] && echo "$want  $dest" | sha256sum -c --quiet - 2>/dev/null; then
    echo "  have $(basename "$dest") (checksum ok)"; return 0
  fi
  echo "  get  $url"
  curl -sSL --fail --retry 3 -o "$dest.part" "$url"
  if [ -n "$want" ]; then
    echo "$want  $dest.part" | sha256sum -c --quiet - || { echo "CHECKSUM MISMATCH for $dest" >&2; rm -f "$dest.part"; exit 1; }
  fi
  mv "$dest.part" "$dest"
}

published_sha() {  # published_sha <checksums-url> <artifact-name>
  curl -sSL --fail "$1" | awk -v n="$2" '$2==n {print $1}'
}

echo "== OPA $OPA_VERSION"
OPA_NAME="opa_linux_${OPA_ARCH}_static"
OPA_URL="https://github.com/open-policy-agent/opa/releases/download/$OPA_VERSION/$OPA_NAME"
if [ "$OPA_ARCH" = arm64 ]; then OPA_SHA=$OPA_SHA_ARM64; else OPA_SHA="$(curl -sSL --fail "$OPA_URL.sha256" | awk '{print $1}')"; fi
fetch "$OPA_URL" "$DL/$OPA_NAME" "$OPA_SHA"
install -m 0755 "$DL/$OPA_NAME" "$BIN/opa"

echo "== Cerbos $CERBOS_VERSION"
CERBOS_TGZ="cerbos_${CERBOS_VERSION}_Linux_${CERBOS_ARCH}.tar.gz"
CERBOSCTL_TGZ="cerbosctl_${CERBOS_VERSION}_Linux_${CERBOS_ARCH}.tar.gz"
CERBOS_BASE="https://github.com/cerbos/cerbos/releases/download/v$CERBOS_VERSION"
if [ "$CERBOS_ARCH" = arm64 ]; then CERBOS_SHA=$CERBOS_SHA_ARM64; CERBOSCTL_SHA=$CERBOSCTL_SHA_ARM64
else CERBOS_SHA="$(published_sha "$CERBOS_BASE/checksums.txt" "$CERBOS_TGZ")"; CERBOSCTL_SHA="$(published_sha "$CERBOS_BASE/checksums.txt" "$CERBOSCTL_TGZ")"; fi
fetch "$CERBOS_BASE/$CERBOS_TGZ" "$DL/$CERBOS_TGZ" "$CERBOS_SHA"
fetch "$CERBOS_BASE/$CERBOSCTL_TGZ" "$DL/$CERBOSCTL_TGZ" "$CERBOSCTL_SHA"
tar -xzf "$DL/$CERBOS_TGZ" -C "$BIN" cerbos
tar -xzf "$DL/$CERBOSCTL_TGZ" -C "$BIN" cerbosctl
chmod 0755 "$BIN/cerbos" "$BIN/cerbosctl"

echo "== OpenFGA $FGA_VERSION"
FGA_TGZ="openfga_${FGA_VERSION}_linux_${FGA_ARCH}.tar.gz"
FGA_BASE="https://github.com/openfga/openfga/releases/download/v$FGA_VERSION"
if [ "$FGA_ARCH" = arm64 ]; then FGA_SHA=$FGA_SHA_ARM64; else FGA_SHA="$(published_sha "$FGA_BASE/checksums.txt" "$FGA_TGZ")"; fi
fetch "$FGA_BASE/$FGA_TGZ" "$DL/$FGA_TGZ" "$FGA_SHA"
tar -xzf "$DL/$FGA_TGZ" -C "$BIN" openfga
chmod 0755 "$BIN/openfga"

if [ "${1:-}" != "--skip-cedar" ]; then
  echo "== Cedar CLI $CEDAR_CLI_VERSION (cargo install, several minutes on first run)"
  if [ -x "$BIN/cedar" ] && "$BIN/cedar" --version 2>/dev/null | grep -q "$CEDAR_CLI_VERSION"; then
    echo "  have cedar $CEDAR_CLI_VERSION"
  else
    cargo install cedar-policy-cli --version "$CEDAR_CLI_VERSION" --locked --root "$ROOT" --quiet
  fi
fi

echo "== wasm3 (Phase 5 A3 combination: OPA wasm on an MCU class interpreter)"
WASM3_COMMIT=40e42cc0f33b24f1db3c632d82cec14084a3a83d
mkdir -p "$ROOT/src"
if [ ! -d "$ROOT/src/wasm3/.git" ]; then git clone -q https://github.com/wasm3/wasm3.git "$ROOT/src/wasm3"; fi
git -C "$ROOT/src/wasm3" checkout -q "$WASM3_COMMIT"
echo "  wasm3 $(git -C "$ROOT/src/wasm3" rev-parse --short HEAD) (MIT, source only, built by groupa/opa_wasm_mcu/Makefile)"

echo "== installed"
for b in opa cerbos cerbosctl openfga cedar; do
  [ -x "$BIN/$b" ] && printf "  %-10s %s\n" "$b" "$(sha256sum "$BIN/$b" | cut -c1-16)"
done
echo "PATH hint: export PATH=\"$BIN:\$PATH\""
