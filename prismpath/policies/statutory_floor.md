---
name: statutory-floor
authority: safety-owner
precedence: floor
---

The baseline that holds everywhere, authored once by whoever tracks the regulatory landscape rather
than re-derived by each flow author. Flow authors may add rules on top; the language has no verb for
removing one, so this file is the guaranteed minimum wherever a guard is built.

Deliberately narrow. A floor that over-blocks gets disabled by whoever it frustrates, and a disabled
floor protects nobody — breadth belongs in domain augmentations that know their own context.

**This is an engineering scaffold, not legal advice.** Every rule here needs counsel review before it
carries a compliance claim, and the citations name the obligation the rule is *aimed at*, not a
verified interpretation of it.

## self-harm
The `as I know it` exclusion is a precision fix, not a carve-out: the benign-collision
corpus caught this rule denying "this refactor is going to end my life as I know it". Narrowing a
pattern is the safety owner editing their own rule; it is not an augmentation weakening the floor,
which the grammar still makes unsayable.

Routes toward support rather than engaging. Deterministic because this must not depend on a small
local model's judgement — the weakest device runs the weakest model, so the guarantee has to be
strongest exactly where the model is least trustworthy.

direction: both
citation: ob.safety_guardrail
message: It sounds like you may be going through something difficult. This tool cannot help with that, but people can — please reach out to a local crisis line.
deny: /\b(kill|hurt|harm)\s+(myself|my ?self)\b/i
deny: /\b(end|ending)\s+(my|it)\s+(life|all)\b(?!\s+as\s+i\s+know)/i
deny: /\bsuicid(e|al)\b/i
deny: /\bself[\s-]?harm\b/i

## weapons-and-explosives
Construction guidance for weapons or explosives, in either direction.

direction: both
citation: ob.safety_guardrail
message: This request falls outside what this tool will help with.
deny: /\b(build|make|construct|assemble|synthesi[sz]e)\b[^.\n]{0,40}\b(bomb|explosive|grenade|firearm|silencer)\b/i
deny: /\b(pipe|pressure[\s-]?cooker)\s+bomb\b/i

## illicit-synthesis
Synthesis routes for controlled substances or chemical weapons.

direction: both
citation: ob.safety_guardrail
message: This request falls outside what this tool will help with.
deny: /\b(synthesi[sz]e|manufacture|cook)\b[^.\n]{0,40}\b(methamphetamine|meth|fentanyl|sarin|vx|ricin|nerve agent)\b/i

## sexual-content-involving-minors
Absolute, both directions, no context in which this is permitted.

direction: both
citation: ob.minor_protection
message: This request is refused.
deny: /\b(child|minor|underage|preteen|pre-teen)\b[^.\n]{0,30}\b(sexual|porn|nude|erotic)\b/i
deny: /\b(sexual|porn|nude|erotic)\b[^.\n]{0,30}\b(child|minor|underage|preteen|pre-teen)\b/i
deny: /\bcsam\b/i

## credential-exfiltration
`AKIAIOSFODNN7EXAMPLE` is AWS's own published documentation placeholder — a learner reading the
AWS docs should not be blocked by it. Excluded by narrowing the pattern.

Text that would carry secrets out of the machine. Outbound-only: a learner discussing the *concept*
of an API key is legitimate, a response *containing* one leaving the device is not.

direction: outbound
citation: ob.data_protection
message: A response was withheld because it appeared to contain credential material.
deny: /\b(AKIA|ASIA)(?!IOSFODNN7EXAMPLE\b)[0-9A-Z]{16}\b/
deny: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/
deny: /\bsk-[A-Za-z0-9]{32,}\b/
deny: /-----BEGIN\s+((RSA|OPENSSH|DSA|EC|PGP)\s+)?PRIVATE KEY-----/
