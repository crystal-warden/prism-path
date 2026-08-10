//! `prismpath-telemetry-rs` — a faithful 1-1 Rust port of `adapters/telemetry/`.

pub mod ackchannel;
pub mod decode;
pub mod epochs;
pub mod packed;
pub mod quantizer;
pub mod selfheal;
pub mod spiral;
pub mod wire;
pub mod zeckendorf;

pub use wire::WireCodec;
