// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Crystal Warden Supply Chain Labs LLC
//! `prismpath-collector`: the one component that holds CAP_BPF. It opens an enforcer's pinned ring buffer
//! (and, for the governed net edge, its counter and configuration maps, read only), drains the decisions,
//! seals them in the RFC 6962 tree and serves them as newline delimited canon/2 records on a Unix socket
//! and, when asked, a loopback port. It takes in nothing but one subscription line per client. README.md
//! has the design, the feed's records and the deployment.

pub mod bpf;
pub mod collector;
pub mod decode;
pub mod feed;
pub mod privs;
pub mod record;
pub mod ring;
pub mod seal;
pub mod source;
