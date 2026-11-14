# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The exemplars the intent centroids are built from.

WRITTEN FRESH FOR THIS LAYER, never taken from the evaluation cases (`cases.py`) or from the adversary set
(`governed_harness/adversary.py`). The cases are this layer's acceptance test; centroids built from them
would be training on the test set and every number measured would mean nothing. `assert_disjoint` checks
it mechanically, as `guard_semantic.SemanticLayer.assert_disjoint_from` does for the P1 layer, and the
lock generator and the tests both call it.

The harm centroids are NOT built here. They are the P1 layer's own centroids, from
`prismpath.safety.guard_semantic.PROHIBITED_INTENT_EXEMPLARS` as frozen in `prismpath/policies/p1_lockfile.json`,
reused unchanged so the harm signal is exactly the one the P1 measurement characterised.

Each intent exemplar is phrased as a request a person gives a coding agent about its workspace. The
classes, in their fixed order (the order breaks a tie, which then has margin 0 and adds nothing):

  inspect            read, list, search, explain; nothing is to change
  modify-workspace   create or edit files in the workspace, and commit them locally
  cleanup            delete what is no longer needed
  vcs-publish        push commits or tags to a remote
  toolchain-change   change the compilers, interpreters or build tools the project runs on
  network            reach a host: download, fetch, install from an index, query a service

`unknown` is not a centroid. It is the class of a reading with no verified embedder, or of an empty task.
"""
from __future__ import annotations

from typing import Dict, Iterable, List

INTENT_CLASSES = ("inspect", "modify-workspace", "cleanup", "vcs-publish", "toolchain-change", "network")
UNKNOWN = "unknown"
ALL_CLASSES = INTENT_CLASSES + (UNKNOWN,)

INTENT_EXEMPLARS: Dict[str, List[str]] = {
    "inspect": [
        "Tell me what is inside the config file.",
        "Show me the contents of the main module.",
        "How many functions are defined in utils.py?",
        "Look through the source and explain how the parser works.",
        "Which files in the project mention the word deadline?",
        "Print the current branch and the recent history.",
        "What does the changelog say about the last release?",
        "Report the size of each file in the data folder.",
        "Search the code for calls to the open function and list them.",
        "Describe the layout of this repository.",
        "Read the test file and tell me which cases it covers.",
        "Explain what the setup script would do, without running it.",
    ],
    "modify-workspace": [
        "Add a docstring to the parse function in parser.py.",
        "Create a new file called todo.md with three bullet points.",
        "Fix the typo in the heading of index.html.",
        "Rename the variable tmp to buffer throughout main.py.",
        "Write a unit test for the add function.",
        "Update the version string in setup.cfg to 1.2.0.",
        "Append a section about installation to the guide.",
        "Change the default port in config.yaml to 9090.",
        "Implement the missing divide function in calc.py.",
        "Stage and commit the changes you made to the docs.",
        "Refactor the loop in report.py into a helper function.",
        "Put a license header at the top of the new source file.",
    ],
    "cleanup": [
        "Remove the leftover temporary files from the last run.",
        "Delete the backup copy of the database dump.",
        "Get rid of the unused draft documents.",
        "Clear out the cache folder, nothing in it is needed.",
        "Throw away the stale lock file.",
        "Tidy the project by deleting generated artifacts.",
        "Erase the old debug output.",
        "Prune the obsolete scripts that nobody calls anymore.",
        "Clean the working directory of compiled objects.",
        "Discard the empty placeholder files.",
    ],
    "vcs-publish": [
        "Push my branch to the shared remote.",
        "Publish the release tag to the server.",
        "Upload the latest commits so the team can see them.",
        "Send the feature branch upstream for review.",
        "Sync the local main branch to the remote repository.",
        "Make the new commits available on the hosting service.",
        "Overwrite the remote branch with the rewritten history.",
        "Share the finished work by pushing it out.",
    ],
    "toolchain-change": [
        "Upgrade the compiler the project builds with.",
        "Switch the Python interpreter to a newer version.",
        "Replace the build tool's wrapper script.",
        "Change which linker the toolchain uses.",
        "Patch the bundled runtime library.",
        "Reconfigure the toolchain directory for the new release.",
        "Pin a different version of the formatter in the toolchain.",
        "Repair the broken interpreter launcher.",
    ],
    "network": [
        "Download the dataset from the project website.",
        "Retrieve the newest revision from the server.",
        "Check whether the remote API is responding.",
        "Install the dependencies from the package index.",
        "Pull the updated submodules from their remotes.",
        "Grab the latest schema from its URL.",
        "Query the status page over HTTP.",
        "Mirror the upstream repository locally.",
    ],
}


def _norm(text: str) -> str:
    return " ".join(text.strip().lower().split())


def assert_disjoint(texts: Iterable[str]) -> None:
    """Fail loudly if any exemplar appears among `texts` (the evaluation tasks, replies and contents)."""
    exemplars = {_norm(text) for values in INTENT_EXEMPLARS.values() for text in values}
    overlap = sorted({_norm(text) for text in texts} & exemplars)
    if overlap:
        raise AssertionError(f"intent exemplars overlap the evaluation cases (training on the test set): {overlap}")
