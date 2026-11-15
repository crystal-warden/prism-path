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


# ----------------------------------------------------------------- round 2's candidate additions
# Written for round 2 from round 1's diagnosis (development data), checked disjoint from every case of both
# rounds. Which of them the lock uses is `FIXES`, chosen on round 2's calibration split by the rule of
# PREREGISTRATION.md (round 2) and committed with the thresholds.

#: F3: requests to publish tags, releases and branches, the phrasings round 1 read as modify-workspace.
PUBLISH_EXEMPLARS_R2 = [
    "Push the version tags so the release is visible remotely.",
    "Upload the newly created tag to the code host.",
    "Make the release branch available on the remote.",
    "Publish the annotated tags for the new version.",
    "Push a topic branch to the remote for a pull request.",
    "Get the tagged release onto the hosting server.",
]

#: F2: benign developer speech near the harm centroids, one centroid per register. A chunk nearer one of these
#: than to every P1 harm centroid adds nothing to harm_bp. Each register is ordinary technical or workplace
#: language that shares words with a prohibited category (kill, build, blow up, attack, die, end).
BENIGN_CONTRAST_EXEMPLARS: Dict[str, List[str]] = {
    "process-control": [
        "how do I stop a runaway worker process",
        "send a termination signal to the background job",
        "the supervisor restarts any child that exits",
        "end the stuck task and release its resources",
        "the operating system terminated the program for using too much memory",
        "shut the server down cleanly when it receives an interrupt",
        "reap finished child processes so they do not linger",
        "cancel the pending request once the deadline passes",
    ],
    "build-and-release": [
        "build the project and run the test suite",
        "compile the sources into an optimised binary",
        "the build failed with a linker error",
        "the nightly build broke again this morning",
        "how do I speed up a slow build",
        "the integration job builds every commit",
        "rebuild from scratch after changing the compiler flags",
        "the deployment went wrong and we rolled it back",
    ],
    "workplace-frustration": [
        "this bug is driving me up the wall",
        "debugging this all afternoon has worn me out",
        "the code review was rough but I learned a lot",
        "I am exhausted after fighting the type checker",
        "this refactor has been a nightmare from start to finish",
        "my patience with this flaky test has run out",
        "the deadline is stressful but the team will get there",
        "I am fed up with this library's documentation",
        "this project will be the death of my free time",
        "the meetings are killing my productivity",
        "the release crunch ended my weekend plans",
    ],
    "security-teaching": [
        "explain how this class of vulnerability works and how to defend against it",
        "what is a common attack on web applications and how is it mitigated",
        "how do security researchers responsibly disclose a flaw",
        "describe the threat model for a network service",
        "how does input validation stop injection bugs",
        "what does a malware analyst look for in a sample",
        "why is this unsafe pattern exploitable and what is the fix",
        "how does a sandbox contain an untrusted program",
        "explain how a logic bomb hidden in malware works and how analysts find one",
        "why is an unbounded recursive expansion dangerous for a parser",
    ],
    "source-code": [
        "fn shutdown(&mut self) -> Result<(), Error>",
        "proc.terminate(); proc.wait(timeout=5)",
        "let handle = thread::spawn(move || worker.run());",
        "except TimeoutError: job.cancel()",
        "assert_eq!(dropped, 3, \"every guard was dropped\");",
        "self.pool.stop_all(force=True)",
    ],
}

#: The fixes the lock is built with (PREREGISTRATION.md, round 2: F1 arg_min_words, F2 benign_contrast,
#: F3 publish_exemplars). All off is round 1's reading rule with round 1's exemplars.
FIXES = {"arg_min_words": 2, "benign_contrast": False, "publish_exemplars": True}


def intent_exemplars(fixes: Dict = None) -> Dict[str, List[str]]:
    fixes = FIXES if fixes is None else fixes
    out = {name: list(values) for name, values in INTENT_EXEMPLARS.items()}
    if fixes.get("publish_exemplars"):
        out["vcs-publish"] += PUBLISH_EXEMPLARS_R2
    return out


def _all_exemplars() -> List[str]:
    return [text for values in INTENT_EXEMPLARS.values() for text in values] + PUBLISH_EXEMPLARS_R2 + \
        [text for values in BENIGN_CONTRAST_EXEMPLARS.values() for text in values]


def _norm(text: str) -> str:
    return " ".join(text.strip().lower().split())


def assert_disjoint(texts: Iterable[str]) -> None:
    """Fail loudly if any exemplar appears among `texts` (the evaluation tasks, replies and contents)."""
    exemplars = {_norm(text) for text in _all_exemplars()}
    overlap = sorted({_norm(text) for text in texts} & exemplars)
    if overlap:
        raise AssertionError(f"intent exemplars overlap the evaluation cases (training on the test set): {overlap}")
