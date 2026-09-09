# prismpath-reflect-bindings

Derive the Facet wire's field bindings from existing Rust types instead of declaring them by hand,
using the third party `facet` reflection crate. This is an onboarding and migration aid: a type the
application already has is reflected, its fields are matched to the policy's declared fields and
kinds, and readings are produced from values of that type.

**Naming.** This crate was `prismpath-facet-bridge` until September 2026; it was renamed because `facet`
is the reflection crate it depends on, unrelated to Facet, PrismPath's decision telemetry wire, and a
name carrying both was a claim nobody made. The dependency stays; the name now says what the crate does.

**What it provides.** `bind` matches a reflected type against the expected `(field, kind)` list and
returns a `Binding` or a `BindError`; `reading_from` turns a value of the bound type into a reading
the wire (`prismpath-telemetry-rs`) can quantize. A missing field or an unrepresentable kind (an
`f64` on a policy field, for example) fails at bind time, not at the wire.

**What enforces it.** `tests/test_reflect_bindings.rs`: bind and reading round trip, missing field
fails bind, unrepresentable kind fails bind. Run `cargo test` in this directory. This crate is not
in the workspace or the CI matrix yet, and it pins a release candidate of the reflection crate
(`facet 0.50.0-rc.6`).

**Depends on.** `prismpath-rs` and `prismpath-telemetry-rs` by path.
