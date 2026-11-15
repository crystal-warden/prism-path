# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The population's limits, one place. The admission image is generated from them (gen_policy.py), the
second reading of the rules states them again (owner_rules.py), and the exhaustive check holds both."""

CAP = 16                 # live members of the whole population, the root included
QUOTA = 6                # live members of one lineage (the subtree of a first generation member)
PER_REQUEST = 2          # children one replication request may ask for
MAX_GENERATION = 3       # the root is generation 0; no member deeper than 3
LINE_REFUSALS = 8        # receipted refusals of one lineage at which it is escalated and stopped
EVAL_CASES = 51          # the harness's adversary set, every case of which a canary must run

# A member's rights. read is everyone's and is not a right. write: the write and delete file tools;
# exec: run_command and git; replicate: replication requests. Signing a policy is not a right at all:
# only the operator's authority key signs one, and no member ever holds it.
RIGHTS = ("write", "exec", "replicate")
TOOLS = {"write": ("write_file", "delete_path"), "exec": ("run_command", "git")}
READ_TOOLS = ("list_dir", "read_file")
