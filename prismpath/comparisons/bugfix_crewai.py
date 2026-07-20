"""bugfix_crewai.py — the `bugfix` flow expressed in CrewAI, as an Area-5 baseline.

Reference implementation (requires `pip install crewai`; NOT run in this repo's CI — it needs an
LLM and CrewAI installed). Its purpose is the comparison, not execution: it shows *where CrewAI's
control flow lives* versus prismpath's.

CrewAI has two paradigms; neither closes the gap prismpath occupies.

1. Crews (Agent / Task / Process.sequential | hierarchical). The sequential process is rigid
   turn-taking: task 1 -> task 2 -> task 3, no conditional branching on a semantic outcome at all.
   You cannot say "if the bug is a duplicate, close; else implement" without leaving the model.
   The hierarchical process delegates routing to a manager LLM — flexible, but non-deterministic
   and unauditable (the manager decides, opaquely, every time).

2. Flows (crewai.flow: @start / @listen / @router) — the paradigm used below, because it is the
   *fairer* comparison: CrewAI Flows CAN branch. But the routing lives in **Python `@router`
   methods** — imperative code that inspects state and returns a label. That is exactly
   LangGraph's problem restated: the control flow is code, not a readable artifact; there are no
   per-edge conditions a PM can read; there is no deterministic/semantic tier distinction; and
   there is no routing-cost model. A bad route traces to a Python method, not to a heading and a
   condition in a document.

Contrast — the same routing in prismpath (`flows/bugfix.md`) is authored, diffable prose:

    ## triage
    -> implement: the bug is reproduced and the root cause is clear
    -> gather_info: it cannot be reproduced or more information is needed
    -> close: it is a duplicate or an invalid report

    ## implement
    -> review: when tests_pass
    -> implement: when visits < 4 and not tests_pass
    -> triage: a design decision is required before continuing

prismpath routes those with deterministic `when` predicates (free, exact) and embedding similarity
for the intent edges (escalating to one LLM call only on low margin). CrewAI has neither the
readable per-edge condition nor the cost model — see comparisons/README.md.
"""
from __future__ import annotations

try:
    from crewai import Agent, Crew, Process, Task
    from crewai.flow.flow import Flow, listen, router, start
    from pydantic import BaseModel
    HAVE_CREWAI = True
except Exception:                                    # keep the file importable without crewai
    HAVE_CREWAI = False
    BaseModel = object                               # type: ignore


class BugfixState(BaseModel if HAVE_CREWAI else object):
    report: str = ""
    outcome: str = ""          # the worker's latest natural-language outcome
    visits: int = 0            # implement-loop counter (prismpath gives you `visits` for free)
    tests_pass: bool = False


def _worker(role: str, goal: str) -> "Agent":
    return Agent(role=role, goal=goal, backstory=f"You are the {role} on a small dev team.",
                 verbose=False, allow_delegation=False)


if HAVE_CREWAI:

    class BugfixFlow(Flow[BugfixState]):
        """The bugfix graph. Note that EVERY routing decision below is a Python method — the thing
        prismpath keeps in the document instead."""

        @start()
        def triage(self):
            agent = _worker("triager", "Understand the bug report and decide what to do next.")
            task = Task(description=f"Triage this report:\n{self.state.report}",
                        expected_output="A short judgement of what to do next.", agent=agent)
            self.state.outcome = str(Crew(agents=[agent], tasks=[task],
                                          process=Process.sequential).kickoff())
            return "triaged"

        @router(triage)
        def route_triage(self):
            # ROUTING IN CODE: substring heuristics standing in for what prismpath expresses as three
            # readable semantic edges. There is no margin, no escalation, no cost model — and no way
            # for a non-engineer to read or lint this.
            o = self.state.outcome.lower()
            if "duplicate" in o or "invalid" in o:
                return "close"
            if "reproduce" in o and "root cause" in o:
                return "implement"
            return "gather_info"

        @listen("gather_info")
        def gather_info(self):
            self.state.outcome = "gathered more information; re-triaging"
            return "triaged"                          # loops back — another @router pass

        @listen("implement")
        def implement(self):
            self.state.visits += 1
            agent = _worker("implementer", "Write or revise the fix and run the tests.")
            task = Task(description="Implement the fix and report whether tests pass.",
                        expected_output="Outcome text; set tests_pass.", agent=agent)
            self.state.outcome = str(Crew(agents=[agent], tasks=[task],
                                          process=Process.sequential).kickoff())
            # the boolean the prismpath `when tests_pass` predicate would read — here it's re-derived
            # from prose in Python, the exact fragility prismpath's structured-field routing avoids.
            self.state.tests_pass = "all tests pass" in self.state.outcome.lower()
            return "implemented"

        @router(implement)
        def route_implement(self):
            if self.state.tests_pass:
                return "review"
            if self.state.visits >= 4:
                return "give_up"
            if "design decision" in self.state.outcome.lower():
                return "triaged"                      # back to triage
            return "implement"                        # loop

        @listen("review")
        def review(self):
            self.state.outcome = "the change looks correct and is ready to merge"
            return "reviewed"

        @router(review)
        def route_review(self):
            return "done" if "ready to merge" in self.state.outcome.lower() else "implement"

        @listen("done")
        def done(self):
            return "done"

        @listen("close")
        def close(self):
            return "closed"

        @listen("give_up")
        def give_up(self):
            return "gave_up"


def main():
    if not HAVE_CREWAI:
        print("crewai not installed — this is a reference baseline for comparisons/README.md.\n"
              "Install with `pip install crewai` to run it.")
        return
    flow = BugfixFlow()
    flow.state.report = "Clicking the export button does nothing on large datasets."
    flow.kickoff()
    print("final:", flow.state.outcome)


if __name__ == "__main__":
    main()
