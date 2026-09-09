# prismpath-facet-bridge

Derive the Facet wire's field bindings from existing Rust types instead of declaring them by hand,
using the third party `facet` reflection crate. This is an onboarding and migration aid: a type the
application already has is reflected, its fields are matched to the policy's declared fields and
kinds, and readings are produced from values of that type.

**Naming.** `facet` here is the reflection crate on crates.io. It is unrelated to Facet, PrismPath's
decision telemetry wire, which this bridge feeds. The collision is accidental and is noted here so
nobody reads a dependency as a claim.

**What it provides.** `bind` matches a reflected type against the expected `(field, kind)` list and
returns a `Binding` or a `BindError`; `reading_from` turns a value of the bound type into a reading
the wire (`prismpath-telemetry-rs`) can quantize. A missing field or an unrepresentable kind (an
`f64` on a policy field, for example) fails at bind time, not at the wire.

**What enforces it.** `tests/test_facet_bridge.rs`: bind and reading round trip, missing field
fails bind, unrepresentable kind fails bind. Run `cargo test` in this directory. This crate is not
in the workspace or the CI matrix yet, and it pins a release candidate of the reflection crate
(`facet 0.50.0-rc.6`).

**Depends on.** `prismpath-rs` and `prismpath-telemetry-rs` by path.
