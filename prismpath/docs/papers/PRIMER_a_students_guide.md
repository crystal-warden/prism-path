# The Cheapest Question First: A Student's Guide to PrismPath (and Why It Also Catches Hackers)

*An on-ramp to the two big papers in this folder — `prismpath_paper_research.md` (the research paper)
and `prismpath_whitepaper_engineering.md` (the engineering white paper). No CS degree required. If you
can follow a recipe and you've argued with a chatbot, you're qualified. ~20 minute read.*

---

## Start here: a tiny story

You're running a help desk. A ticket comes in. You have to decide: *is this a bug, a duplicate, or a
"we need more info" case?* Some tickets are obvious from a keyword ("error code 500" → bug). Some need
you to actually *read and judge* ("the thing feels slow sometimes"). A few need your senior engineer.

Now imagine you had to automate this with an AI. You could:

- **(A)** Write rigid `if` rules in code. Fast and predictable — but only a programmer can change them,
  and they can't handle the fuzzy "feels slow" tickets.
- **(B)** Ask a large AI model to decide *every single ticket.* Handles fuzziness — but it's slow,
  costs money/electricity every time, and it's weirdly bad at simple logic (more on that soon).

Most tools force you to pick A or B. **PrismPath's whole idea is: you shouldn't have to. Use the cheapest
tool that actually answers the question, and only "phone the expert" when you're genuinely stuck.**

That one sentence is 80% of both papers. The rest is *how to do it safely and prove it works.*

---

## The One Big Idea: "control flow is data, not code"

Normally, the logic of a program — the *"if this, then go there"* — is buried inside code only a
programmer can read. PrismPath writes that logic as a plain **Markdown file** (the same kind of text file
this document is). Each step is a heading; each decision is a line of English like:

```
-> implement: the bug is reproduced and the root cause is clear
-> gather_info: it cannot be reproduced or more information is needed
```

A project manager, a doctor, a security analyst — anyone who owns the actual process — can *read and
edit the logic itself*, not a translation of it. And because the logic is now **data (text) instead of
code**, you can do things to it you normally can't do to a program: diff it, draw it, lint it for
mistakes, test it without running any AI, and lock it so it can't silently change. (Research paper §2.1
is the "look what becomes possible" list. It's genuinely cool; skim it.)

---

## Idea 1 — The "cheapest question first" ladder (the *routing spectrum*)

When PrismPath reaches a decision, it tries mechanisms from cheap to expensive:

1. **Is it pure logic?** ("did 3 tests fail?", "have we tried this 5 times?") → answer it with plain,
   exact rules. **Free. Never wrong.**
2. **Is it a matter of meaning/intent?** ("does this outcome *sound like* 'ready to ship'?") → use an
   **embedding** (see the box below) to measure similarity. **Almost free.**
3. **Only if the embedding is unsure** → call the big expensive AI. **Rare.**

> **What's an embedding?** A way to turn a sentence (or a photo, or a chunk of network traffic) into a
> list of numbers — coordinates in space — so that *similar things land close together.* "The tests
> passed" and "all checks are green" end up near each other; "banana" lands far away. Measuring
> similarity is then just measuring distance. It's the workhorse of modern AI, and you'll meet it in
> every domain.

The measured payoff (research paper §4.4): against the popular tools that call the AI on *every*
decision, PrismPath hits **~84% accuracy using 2.6× fewer AI calls and about half the typical latency** —
because it's the only one that knows how to *not* make the expensive call. (It's honest about the
catch, too: the occasional "phone the expert" hop is slower, so PrismPath wins on *average* speed but
loses on *worst-case* speed. Real engineering has trade-offs; good papers name them.)

---

## Idea 2 — The trap that shows up *everywhere*: "sounds right" ≠ "is right"

Here's the finding that, once you see it, you'll notice in every AI system you ever touch.

Embeddings are fantastic at **topic** ("this is about tests") but terrible at **logical flips**. To an
embedding, *"the tests passed"* and *"the tests did **not** pass"* look almost identical — same words,
same topic — even though they mean opposite things. In the paper's benchmark, embedding routing scored
0.81 on intent questions but **collapsed to 0.52 — basically a coin flip — on these "polarity" cases**
(§4.2).

And it gets subtler. Sometimes the AI is **confidently wrong** — not "hmm, 51/49," but "definitely
this!" while being definitely wrong. You can't fix a *confident* mistake by asking "are you unsure?" —
it isn't unsure. The paper's answer (§4.3) is to **learn from examples of what the right answer
actually looked like in the past** (called *centroids*) instead of trusting the AI's gut. That single
move rescued the coin-flip cases from 0.52 up to 0.75.

**Remember this trap. It's about to reappear in a completely different field.**

---

## Idea 3 — "Pics or it didn't happen" (gates)

The last big idea is a discipline, not an algorithm. An AI agent will happily tell you *"Done! I built
the feature!"* — and be wrong. PrismPath's rule: **never accept a claim a machine can't verify.** A task
isn't "done" because the AI says so; it's done when it *compiles, passes tests, and is actually wired
in.* These checks are called **gates**, and the motto is *"never write a completeness claim a gate
doesn't enforce."* (Research paper §5, engineering paper throughout.) It's a good rule for your own
homework, honestly.

---

## The plot twist: the same idea catches hackers

Now the fun part — and a live example of research **generalizing across domains**.

The team built a security system that watches network traffic for malware. It uses the *exact same
recipe*: a **cheap** detector (an embedding of the traffic, compared against a library of known-bad
traffic) as the front line, and the **expensive** AI (a reasoning model) only for the suspicious
residue. Cheap-first, escalate-on-doubt — Idea 1, in a security uniform.

But it started raising false alarms: ordinary web browsing to big cloud services (think Netflix's or
Microsoft's servers) got flagged as **malware**. Why? Because — *here's Idea 2 again* — benign web
traffic **"sounds like"** malicious web traffic to the embedding. They land close together. Same
"sounds right ≠ is right" trap, now with packets instead of sentences.

And the fix was the *same fix*: the detector only knew what **bad** looked like; it had no idea what
**normal** looked like. So they built a library of *normal* traffic too, and changed the question from
*"is this close to something bad?"* to *"is this closer to bad than it is to normal?"* Result
(measured on the real system): false alarms dropped from ~2% to a **mathematically certified under
0.05%** — while still catching the real malware it caught before. **Zero cost to detection, ~40× fewer
false alarms.** (This is written up in the two `CONTRIB_outline_*` files next to this one.)

That "mathematically certified" part is worth pausing on: instead of *guessing* a cutoff and hoping,
they used statistics (a *Wilson bound*) to **prove** the error stays low *even on traffic they haven't
seen yet.* Guessing a magic number is what amateurs do; proving a bound is what the field respects.

---

## Cheat sheet: jargon → plain English → where to read more

| You'll see this word… | It really means… | Go deeper |
|---|---|---|
| **Control flow** | The "what happens next" logic of a program | Research §1 |
| **Routing / edge** | A decision about which step to go to next | Research §3.2 |
| **Routing spectrum** | Cheap-first ladder of decision tools | Research §3.2 |
| **Embedding** | Turning things into coordinates so "similar = close" | Research §3.2 box |
| **Semantic** | Based on *meaning* (vs exact logic) | Research §3.2 |
| **Margin / confidence** | How sure the cheap tool is; escalate if unsure | Research §3.2, §4.3 |
| **Polarity trap** | AI confuses "X" with "not X" | Research §4.2 |
| **Confident error** | Wrong *and* sure — the hardest case | Research §4.3 |
| **Centroid** | Learn from past correct answers, not the AI's gut | Research §4.3 |
| **Calibration / Wilson bound** | *Prove* the error rate is low, don't guess a cutoff | Research §4.3 |
| **Gate** | A machine-checkable definition of "done" | Research §5 |
| **False positive (FP)** | A false alarm | CONTRIB outlines |
| **Guardrail** | A safety rule the system must never break | Engineering paper |

---

## Why you should care (this is a multi-domain toolkit)

The three ideas aren't about workflows or hacking specifically — they're about **any system that has to
make lots of decisions under uncertainty.** That's almost everything:

- **Medicine:** triage which patient charts a doctor must read vs which are routine — and *"sounds
  urgent" ≠ "is urgent"* is a literal life-or-death version of the polarity trap.
- **Law / finance:** route the 5% of contracts that need a human expert; prove your error bound to a
  regulator.
- **Customer support, content moderation, scientific literature search**… same shape.
- **Running AI affordably:** the "don't call the expensive model unless you must" idea is how you make
  AI cheap enough to actually deploy — a whole skill called *capacity engineering* (how many things can
  one computer watch before it falls over?).

The meta-lesson: **a good idea in one field is often the same idea in ten others.** The security fix in
this project is *literally the workflow paper's finding, wearing a different costume.* Spotting those
bridges is what research is.

---

## Open problems (a.k.a. things *you* could work on)

These are real, unfinished, and student-sized on-ramps:

1. **Where else does the "confident-error" trap hide?** Pick a domain you know (game reviews? recipes?
   lab reports?). Does the AI confuse opposites there too? Measuring it is a legit mini-project.
2. **Catching *confident* mistakes, not just unsure ones.** The margin trick only catches "the AI is
   unsure." Confident-but-wrong is still open. Better detectors for it would be a real contribution.
3. **Teaching a system "what's normal" — safely.** The malware fix depends on a good library of normal
   traffic. How do you keep it fresh without an attacker sneaking "normal-looking" bad stuff in? (This
   project is literally collecting that data right now — see task #35.)
4. **Does it survive a language change? A different embedding model?** The papers test one English
   model. Nobody's checked others. Easy to start, genuinely useful.
5. **When should a machine give up and ask a human?** "Route to a person" as a first-class, well-timed
   move is barely explored (research §7).
6. **The economics.** If one box can watch N networks, what's N, and what breaks first — the AI, the
   storage, the network? Measuring ceilings is unglamorous and extremely employable.

---

## How to actually start

1. Read **this file** (done!). 2. Read the research paper's **Abstract, §1, and §4.2–4.3** — that's the
heart. 3. Skim the engineering paper for the *"how do you run this without it breaking at 3am"* stories.
4. Then open a flow file (`prismpath/gallery/`) and read it like the recipe it is. 5. Find one of the six
open problems above that annoys you in a good way, and poke at it.

The whole system is small enough for one person to read end-to-end. That's rare, and it's the point:
**you don't need permission or a lab to start doing this. You need a question and the cheapest tool
that answers it.**
