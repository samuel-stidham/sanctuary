//! The disable, delete, and purge verbs: taking a version or a secret
//! out of use.

use super::cli::Globals;
use super::{Error, hint, open_vault, print_json};
use crate::json::Json;
use crate::quote::quote;
use crate::vault::{self, State, Vault};
use crate::warn;

/// Takes one version out of resolution without touching its envelope.
pub fn disable(globals: &Globals, name: &str, version: &str) -> Result<(), Error> {
    let number: i64 = version
        .parse()
        .map_err(|_| Error::Message(format!("version must be a number, got {}", quote(version))))?;

    let vault = open_vault(globals)?;

    vault.disable(name, number).map_err(hint::vault)?;

    let mut output = vec![("name", Json::from(name))];

    // The Go original leaves a zero version out of its output.
    if number != 0 {
        output.push(("version", number.into()));
    }

    output.push(("result", State::Disabled.as_str().into()));

    print_json(globals, &Json::Object(output))
}

/// Hides the secret from list and get. Versions and envelopes stay.
pub fn delete(globals: &Globals, name: &str) -> Result<(), Error> {
    let vault = open_vault(globals)?;

    vault.soft_delete(name).map_err(hint::vault)?;

    print_json(
        globals,
        &Json::Object(vec![("name", name.into()), ("result", "deleted".into())]),
    )
}

/// Erases every envelope of the secret for good.
pub fn purge(globals: &Globals, name: &str, confirmed: bool) -> Result<(), Error> {
    if !confirmed {
        return Err(Error::Message(
            "purge destroys envelopes forever: re-run with --yes to confirm".to_owned(),
        ));
    }

    let mut vault = open_vault(globals)?;
    let destroyed = vault.purge(name).map_err(hint::vault)?;

    warn_if_checkpoint_blocked(&vault);

    print_json(
        globals,
        &Json::Object(vec![
            ("name", name.into()),
            ("destroyedVersions", destroyed.into()),
            ("result", "purged".into()),
        ]),
    )
}

/// Retries the write-ahead log scrub and warns when it cannot happen.
/// A blocked checkpoint gets the explanation about a concurrent
/// reader. Any other failure prints the real error, so an I/O or
/// permission problem is not blamed on another process.
///
/// The destructive operation is already committed, so this is advice
/// and never a failure. The erased bytes stay recoverable from the log
/// until a later checkpoint truncates it.
pub fn warn_if_checkpoint_blocked(vault: &Vault) {
    match vault.checkpoint() {
        Ok(()) => {}
        Err(vault::Error::CheckpointBlocked) => warn!(
            "another safetybox process is reading the vault, old ciphertext may linger in \
             the write-ahead log until the next checkpoint"
        ),
        Err(err) => warn!(
            "could not scrub the write-ahead log",
            "error" => err.to_string().as_str(),
        ),
    }
}
