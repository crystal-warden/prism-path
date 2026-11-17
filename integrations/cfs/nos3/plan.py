# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Crystal Warden Supply Chain Labs LLC
"""The NOS3 scenario's autonomy plan, the fault playbook, and what the policy must decide for each.

The autonomy app (`pp_autonomy`) proposes the plan's commands one a second after the ground starts it, and the
playbook's commands as soon as it sees the payload report a fault. Each proposal carries its tag in the command's
spare word, which no policy field reads, so the vehicle side can tell the commands apart: the vehicle app turns an
attitude command into a reaction wheel torque of `slew_deg` x 10^-4 N m on wheel 0, and a payload command into the
payload's configuration word, set to the tag.

`EXPECTED` is the outcome table, written by hand from the rules in
`integrations/cfs/prismpath_app/policy/example.rules.md`; the tests hold it to the reference decision path and the
scenario holds the flight run to it.

    python -m integrations.cfs.nos3.plan      # writes pp_autonomy/fsw/src/pp_autonomy_plan.inc from this file
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Dict, List, NamedTuple, Tuple

HERE = Path(__file__).resolve().parent
INCLUDE = HERE / "pp_autonomy" / "fsw" / "src" / "pp_autonomy_plan.inc"

ATTITUDE, THRUSTER, PAYLOAD = 1, 2, 3


class Proposal(NamedTuple):
    tag: int
    what: str
    cmd_class: int
    ground_contact: int
    slew_deg: int
    thrust_pct: int

    def reading(self) -> Dict[str, int]:
        return dict(cmd_class=self.cmd_class, ground_contact=self.ground_contact, slew_deg=self.slew_deg,
                    thrust_pct=self.thrust_pct)


# the plan, proposed in order, one a second. Its payload commands come first: NOS3's sample instrument app halts the
# device on a nonzero status word (its own fault response), so no payload command can reach the instrument after
# the fault, and the scenario injects the fault after the fourth proposal.
PLAN: List[Proposal] = [
    Proposal(1, "attitude: slew 20 deg to the first target, in contact", ATTITUDE, 1, 20, 0),
    Proposal(2, "payload: start the first observation", PAYLOAD, 1, 0, 0),
    Proposal(3, "attitude: slew 120 deg, past the 90 deg limit", ATTITUDE, 1, 120, 0),
    Proposal(4, "payload: start the second observation", PAYLOAD, 1, 0, 0),
    Proposal(5, "attitude: slew 70 deg after contact is lost", ATTITUDE, 0, 70, 0),
    Proposal(6, "command class 7, which the policy does not know", 7, 0, 0, 0),
    Proposal(7, "attitude: slew 60 deg, back in contact", ATTITUDE, 1, 60, 0),
    Proposal(8, "attitude: slew 35 deg, out of contact", ATTITUDE, 0, 35, 0),
]

# the playbook for a payload fault, proposed at once when the payload's status word turns nonzero; the app assumes
# no ground contact when it answers a fault
FAULT_RESPONSE: List[Proposal] = [
    Proposal(101, "fault: slew 30 deg to turn the payload's aperture off the sun", ATTITUDE, 0, 30, 0),
    Proposal(102, "fault: slew 75 deg to the sun safe attitude, no contact", ATTITUDE, 0, 75, 0),
]

# the fault the scenario injects through NOS3's command bus bridge into the payload simulator
FAULT_NODE = "sample-command"
FAULT_COMMAND = "STATUS=3"
FAULT_STATUS = 3

# tag -> (decision kind, registered cause, which rule of example.rules.md decides it)
EXPECTED: Dict[int, Tuple[str, int, str]] = {
    1: ("allow", 0, "nominal commands within limits are allowed"),
    2: ("allow", 0, "nominal commands within limits are allowed"),
    3: ("refuse", 37, "route:contract-violation: attitude slew above 90 deg"),
    4: ("allow", 0, "nominal commands within limits are allowed"),
    5: ("escalate", 34, "route:needs-human: slew above 45 deg without ground contact"),
    6: ("refuse", 104, "agent:unclassifiable: command class outside 1, 2, 3"),
    7: ("allow", 0, "a slew above 45 deg is allowed in contact"),
    8: ("allow", 0, "a slew of 45 deg or less needs no contact"),
    101: ("allow", 0, "a slew of 45 deg or less needs no contact"),
    102: ("escalate", 34, "route:needs-human: slew above 45 deg without ground contact"),
}


def proposals() -> List[Proposal]:
    return PLAN + FAULT_RESPONSE


def by_tag() -> Dict[int, Proposal]:
    return {p.tag: p for p in proposals()}


def torque(p: Proposal) -> int:
    """The reaction wheel torque the vehicle app commands for an attitude proposal, in 10^-4 N m."""
    return p.slew_deg


def vehicle_effects(tags: List[int]) -> Tuple[List[int], List[int]]:
    """(wheel torques, payload configuration words) the simulators must see, in order, for these allowed tags."""
    table = by_tag()
    torques = [torque(table[t]) for t in tags if table[t].cmd_class == ATTITUDE]
    configs = [t for t in tags if table[t].cmd_class == PAYLOAD]
    return torques, configs


def allowed(tags: List[int]) -> List[int]:
    return [t for t in tags if EXPECTED[t][0] == "allow"]


def render() -> str:
    def rows(name: str, items: List[Proposal]) -> str:
        body = "".join(f"    {{{p.tag}, {p.cmd_class}, {p.ground_contact}, {p.slew_deg}, {p.thrust_pct}}}, /* {p.what} */\n"
                       for p in items)
        return f"static const PP_AUTONOMY_Proposal_t {name}[] = {{\n{body}}};\n"
    return ("/* SPDX-License-Identifier: Apache-2.0 */\n"
            "/* Copyright 2026 Crystal Warden Supply Chain Labs LLC */\n"
            "/* Generated by `python -m integrations.cfs.nos3.plan` from integrations/cfs/nos3/plan.py. Do not edit. */\n"
            "/* {tag, cmd_class, ground_contact, slew_deg, thrust_pct} */\n"
            + rows("PP_AUTONOMY_Plan", PLAN) + rows("PP_AUTONOMY_FaultResponse", FAULT_RESPONSE)
            + f"#define PP_AUTONOMY_FAULT_STATUS {FAULT_STATUS}u\n")


def main() -> int:
    INCLUDE.write_text(render())
    print(f"wrote {INCLUDE.relative_to(HERE.parents[2])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
