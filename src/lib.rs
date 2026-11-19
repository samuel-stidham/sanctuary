//! sanctuary: a single-user, versioned secrets vault.
//!
//! This crate is the Rust port of the Go original, and builds the `sanctuary`
//! command. The two share one vault format and one behavior. The
//! conformance suite in `tests/` holds the port to that.
//!
//! The module boundaries are load-bearing. Secrets flow
//! `secret → envelope → vault` and never backward. [`secret`] holds
//! plaintext and nothing else. [`envelope`] seals and opens but never
//! persists. [`vault`] persists but never sees plaintext. [`cmd`] is the single boundary that turns errors into
//! messages that say what to do next.

pub mod cmd;
pub mod color;
pub mod envelope;
pub mod identity;
pub mod json;
pub mod locked;
pub mod logging;
pub mod quote;
pub mod reference;
pub mod secret;
pub mod sys;
pub mod timestamp;
pub mod vault;
