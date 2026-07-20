#!/usr/bin/env bash
# Vendor the Luau/Roblox toolchain into tools/ — the gitignored binaries + Roblox API type defs.
#
# The toolchain (tools/bin/, tools/_src/) and the API defs (tools/defs/) are NOT committed (~60MB);
# this script regenerates them. Run it ONCE on a networked machine, then the whole tools/ tree is a
# self-contained, air-gappable bundle — the gate (luau_gate.py) never hits the network at runtime.
#
# Targets aarch64-linux (the GB10 box). Pinned versions below match what the gate was validated on.
#   luau   0.725  — built from source (luau-lang/luau, cmake)  -> luau, luau-analyze, luau-compile
#   lune   0.10.4 — prebuilt aarch64 (lune-org/lune)
#   rojo   7.6.1  — prebuilt aarch64 (rojo-rbx/rojo)
#   stylua 2.5.2  — prebuilt aarch64 (JohnnyMorganz/StyLua)
#   luau-lsp 1.68.1 — prebuilt arm64 (JohnnyMorganz/luau-lsp)
#   globalTypes.d.luau — Roblox API surface, regenerated from the live API dump (luau-lsp scripts/)
#
# Usage:  bash tools/fetch.sh           # fetch anything missing
#         FORCE=1 bash tools/fetch.sh   # re-fetch everything
set -euo pipefail

LUAU_VER=0.725
LUNE_VER=0.10.4
ROJO_VER=7.6.1
STYLUA_VER=2.5.2
LUAU_LSP_VER=1.68.1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # .../prismpath/tools
BIN="$HERE/bin"
SRC="$HERE/_src"
DEFS="$HERE/defs"
mkdir -p "$BIN" "$SRC" "$DEFS"

have() { [ -z "${FORCE:-}" ] && [ -s "$1" ]; }   # present and non-empty, unless FORCE

fetch_zip() {   # url  archive_member  dest_path
  local url="$1" member="$2" dest="$3"
  if have "$dest"; then echo "  ✓ $(basename "$dest") (cached)"; return; fi
  echo "  → $url"
  local tmp; tmp="$(mktemp -d)"
  curl -fsSL -o "$tmp/a.zip" "$url"
  unzip -qo "$tmp/a.zip" -d "$tmp"
  cp "$tmp/$member" "$dest"
  chmod +x "$dest"
  rm -rf "$tmp"
  echo "  ✓ $(basename "$dest")"
}

echo "[1/3] Roblox API type definitions -> tools/defs/"
if have "$DEFS/globalTypes.d.luau"; then
  echo "  ✓ globalTypes.d.luau (cached)"
else
  curl -fsSL -o "$DEFS/globalTypes.d.luau" \
    https://raw.githubusercontent.com/JohnnyMorganz/luau-lsp/main/scripts/globalTypes.d.luau
  echo "  ✓ globalTypes.d.luau ($(wc -c < "$DEFS/globalTypes.d.luau") bytes)"
fi

echo "[2/3] prebuilt aarch64 binaries -> tools/bin/"
fetch_zip "https://github.com/lune-org/lune/releases/download/v$LUNE_VER/lune-$LUNE_VER-linux-aarch64.zip" \
          "lune" "$BIN/lune"
fetch_zip "https://github.com/rojo-rbx/rojo/releases/download/v$ROJO_VER/rojo-$ROJO_VER-linux-aarch64.zip" \
          "rojo" "$BIN/rojo"
fetch_zip "https://github.com/JohnnyMorganz/StyLua/releases/download/v$STYLUA_VER/stylua-linux-aarch64.zip" \
          "stylua" "$BIN/stylua"
fetch_zip "https://github.com/JohnnyMorganz/luau-lsp/releases/download/$LUAU_LSP_VER/luau-lsp-linux-arm64.zip" \
          "luau-lsp" "$BIN/luau-lsp"

echo "[3/3] luau $LUAU_VER (luau, luau-analyze, luau-compile) -> built from source"
if have "$BIN/luau" && have "$BIN/luau-analyze" && have "$BIN/luau-compile"; then
  echo "  ✓ luau/luau-analyze/luau-compile (cached)"
else
  if [ ! -f "$SRC/luau/CMakeLists.txt" ]; then
    echo "  → cloning luau-lang/luau @ $LUAU_VER"
    git clone --depth 1 --branch "$LUAU_VER" https://github.com/luau-lang/luau "$SRC/luau"
  fi
  echo "  → cmake build (Release; needs cmake + a C++ compiler)"
  cmake -S "$SRC/luau" -B "$SRC/luau/build" -DCMAKE_BUILD_TYPE=Release >/dev/null
  cmake --build "$SRC/luau/build" --target Luau.Repl.CLI Luau.Analyze.CLI Luau.Compile.CLI -j"$(nproc)" >/dev/null
  cp "$SRC/luau/build/luau"         "$BIN/luau"
  cp "$SRC/luau/build/luau-analyze" "$BIN/luau-analyze"
  cp "$SRC/luau/build/luau-compile" "$BIN/luau-compile"
  chmod +x "$BIN/luau" "$BIN/luau-analyze" "$BIN/luau-compile"
  echo "  ✓ luau/luau-analyze/luau-compile"
fi

echo "done. tools/ is now a self-contained, air-gappable bundle."
