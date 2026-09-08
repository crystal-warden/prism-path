#![no_std]
// The attempt (PREREGISTRATION A3): can Cedar's Rust core be built for an MCU class target without
// the standard library? cedar-policy 4.12.0 exposes no `no_std` feature (crates.io feature list), so
// the expected outcome is a std dependency error from the crate or its dependency graph.
extern crate cedar_policy;
#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }
