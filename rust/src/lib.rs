//! Distributed mDNS (Scalable DNS-SD) client library.
//!
//! Implements link-local mDNS/DNS-SD (RFC 6762 / RFC 6763), multi-link Domain Enumeration
//! (RFC 8766 / RFC 8375), DNS Stateful Operations over TLS (RFC 8490), DNS Push Notifications
//! (RFC 8765) with fallback to Apple's Long-Lived Queries (RFC 8764) and unicast polling,
//! plus DNS Dynamic Update with TSIG (RFC 2136 / RFC 2845).

pub mod cache;
pub mod client;
pub mod dso;
pub mod enumeration;
pub mod llq;
pub mod mdns;
pub mod push;
pub mod update;
pub mod wire;
