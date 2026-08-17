// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
// Copy the playground + kernel into media/ for packaging. In REPO DEV MODE this is unnecessary —
// extension.js falls back to ../../portable directly, so the repo never carries duplicates; the
// copy exists only inside a built .vsix (vscode:prepublish runs this).
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const portable = join(here, "..", "..", "..", "portable");
const media = join(here, "..", "media");
mkdirSync(media, { recursive: true });
for (const f of ["playground.html", "prismpath.mjs"]) {
  copyFileSync(join(portable, f), join(media, f));
  console.log(`synced ${f} -> media/`);
}
