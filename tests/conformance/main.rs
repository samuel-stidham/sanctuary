//! Conformance suite: the behavior sanctuary must share with the Go
//! original, pinned at the one surface both implementations expose.
//!
//! Each test names the Go test it ports. Run the suite against the Go
//! binary to prove the expectations are the reference behavior, and
//! against this crate's binary to prove the port matches:
//!
//! ```sh
//! make test-oracle   # the Go reference
//! cargo test         # the Rust port
//! ```
//!
//! `tests/PARITY.md` maps every Go test to its counterpart here, or
//! records why it has none at this surface.

mod support;

mod cli;
mod envelope;
mod envname;
mod exec;
mod identity;
mod init;
mod lifecycle;
mod locks;
mod logging;
mod migrate;
mod plaintext;
mod prompt;
mod rekey;
mod reveal;
mod store;
mod tamper;
mod vault;
