//! What to do next. This is the boundary where an error from another
//! module becomes guidance for the person at the terminal.

use super::Error;
use super::cli::NAME;
use crate::{envelope, identity, vault};

/// What a recipient mismatch can mean, whichever layer reports it.
pub const RECIPIENT_MISMATCH_ADVICE: &str = "the vault may have been tampered with, or an \
     interrupted rekey left the wrong identity in place, check for a .new sibling of the \
     identity file";

/// An identity error, with its advice when there is any.
pub fn identity(err: identity::Error) -> Error {
    let advice = match &err {
        identity::Error::NotFound { .. } => Some(format!("run `{NAME} init` first")),
        identity::Error::UnsafeDirPermissions { .. } => {
            Some("run `chmod 700` on the identity directory".to_owned())
        }
        identity::Error::Exists { .. } => {
            Some("a previous run may have left a stale file, move it aside".to_owned())
        }
        identity::Error::DecryptFailed(_) => Some("check the passphrase".to_owned()),
        identity::Error::UnsafePermissions { .. } => {
            Some("run `chmod 600` on the identity file".to_owned())
        }
        identity::Error::Malformed
        | identity::Error::Rename { .. }
        | identity::Error::NotDurable(_)
        | identity::Error::PassphraseNotText
        | identity::Error::Encrypt(_)
        | identity::Error::File { .. } => None,
    };

    advise(&err.to_string(), advice)
}

/// An envelope error, with its advice when there is any.
pub fn envelope(err: &envelope::Error) -> String {
    match envelope_advice(err) {
        Some(advice) => format!("{err}: {advice}"),
        None => err.to_string(),
    }
}

/// What to do about an envelope error, when there is something to do.
pub fn envelope_advice(err: &envelope::Error) -> Option<String> {
    match err {
        // A legacy frame looks like tampering and almost never is. An
        // older safetybox writing to a migrated vault is the usual
        // cause, and migrate repairs it.
        envelope::Error::Legacy { .. } => Some(format!(
            "an older safetybox most likely wrote this value during or after a migration: \
             run `{NAME} migrate` to repair it, or `set` the secret again"
        )),
        envelope::Error::DecryptFailed { .. } => Some(
            "the identity may not match this vault, check for an interrupted rekey (a .new \
             sibling of the identity file)"
                .to_owned(),
        ),
        envelope::Error::InvalidFrame { .. }
        | envelope::Error::Seal { .. }
        | envelope::Error::AddressMismatch { .. } => None,
    }
}

/// A vault error under `context`, with its advice when there is any.
pub fn vault_in(context: &str, err: vault::Error) -> Error {
    match vault(err) {
        Error::Message(message) => Error::Message(format!("{context}: {message}")),
        other => other,
    }
}

/// A vault error, with its advice when there is any.
pub fn vault(err: vault::Error) -> Error {
    let advice = match &err {
        vault::Error::NotFound { .. } => Some(format!("run `{NAME} init` first")),
        vault::Error::Corrupt { .. } => Some(format!(
            "the file at the vault path looks half-created, likely from an interrupted init: \
             inspect it, move it aside, then run `{NAME} init`"
        )),
        vault::Error::Exists { .. } => Some(
            "if a previous init was interrupted, this may be a half-created husk: inspect it \
             and move it aside before retrying"
                .to_owned(),
        ),
        vault::Error::FormatVersion { .. } => Some(format!(
            "if this vault is from an older safetybox, run `{NAME} migrate` to upgrade it, \
             otherwise upgrade safetybox to open it"
        )),
        vault::Error::StoredTimeCorrupt { .. } => Some(
            "no safetybox writer produces that value, so the column was edited outside \
             safetybox: `set` the named secret again to rewrite its timestamps"
                .to_owned(),
        ),
        vault::Error::SecretDeleted { .. } => {
            Some("`set` a new value to revive it or `purge` it for good".to_owned())
        }
        vault::Error::VersionNotFound { .. } => {
            Some("`show` the secret to see its versions".to_owned())
        }
        vault::Error::Reseal { advice, .. } => advice.clone(),
        // The same mismatch has three causes, from innocent to
        // hostile, and the read verbs name all three.
        vault::Error::RecipientMismatch { .. } => Some(RECIPIENT_MISMATCH_ADVICE.to_owned()),
        vault::Error::AlreadyCurrent
        | vault::Error::NotMigratable { .. }
        | vault::Error::SecretNotFound { .. }
        | vault::Error::VersionDestroyed { .. }
        | vault::Error::CheckpointBlocked
        | vault::Error::InvalidName { .. }
        | vault::Error::Seal { .. }
        | vault::Error::CommitAmbiguous { .. }
        | vault::Error::File { .. }
        | vault::Error::Database { .. } => None,
    };

    advise(&err.to_string(), advice)
}

fn advise(message: &str, advice: Option<String>) -> Error {
    Error::Message(match advice {
        Some(advice) => format!("{message}: {advice}"),
        None => message.to_owned(),
    })
}
