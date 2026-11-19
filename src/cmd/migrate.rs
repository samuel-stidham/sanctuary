//! The migrate verb: an older vault upgraded to the current format.
//!
//! Every value is re-sealed into the current envelope, which binds the
//! env name and expiry into it. Re-sealing decrypts each value, so the
//! verb needs the passphrase. The identity and the recipient do not
//! change.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use super::cli::Globals;
use super::decrypt::load_identity;
use super::{Error, hint, lock, paths, print_json};
use crate::envelope::{self, Bound};
use crate::json::Json;
use crate::sys::PathError;
use crate::vault::{self, MigrateRow, ResealFailure, Resealed, canonical_address};
use crate::{info, warn};

pub fn run(globals: &Globals) -> Result<(), Error> {
    let vault_path = paths::vault(globals.vault.as_deref(), &paths::process_env)?;

    // Refuse a missing vault before taking the lock. Locking first
    // would leave an empty lock file beside nothing, in a directory
    // that happened to exist. A lock file is permanent by design once
    // a vault exists, so it could not be removed afterward.
    require_vault_file(&vault_path)?;

    // Serialize against another migrate of the same vault, before the
    // identity is loaded or a write transaction opens. Without this,
    // the loser of two runs waits on the write lock and can time out
    // with a raw busy error, not this clear refusal.
    let _lock = lock::acquire_migrate(&vault_path)?;

    let key = load_identity(globals)?;
    let recipient = key.to_public();
    let stored_recipient = recipient.to_string();

    let migrated = vault::migrate(&vault_path, &stored_recipient, |row| {
        migrate_reseal(&key, &recipient, &row)
    });

    let count = match migrated {
        Ok(count) => count,
        Err(vault::Error::AlreadyCurrent) => {
            return repair_stragglers(globals, &vault_path, &key, &recipient);
        }
        // The usual advice for a format mismatch is to run migrate,
        // which is the command that just failed. A format newer than
        // this build understands needs a newer build.
        Err(err @ vault::Error::NotMigratable { .. }) => {
            return Err(Error::Message(format!(
                "{err}: upgrade safetybox to open a vault in a newer format"
            )));
        }
        Err(err) => return Err(hint::vault(err)),
    };

    print_json(globals, &output(count, "migrated"))
}

fn output(count: i64, result: &'static str) -> Json {
    Json::Object(vec![
        ("migratedVersions", count.into()),
        ("result", result.into()),
    ])
}

/// Refuses unless a regular file sits at the vault path.
fn require_vault_file(vault_path: &Path) -> Result<(), Error> {
    match fs::metadata(vault_path) {
        Ok(metadata) if metadata.is_file() => Ok(()),
        Ok(_) => Err(hint::vault(vault::Error::Corrupt {
            path: vault_path.to_owned(),
        })),
        Err(err) if err.kind() == ErrorKind::NotFound => Err(hint::vault(vault::Error::NotFound {
            path: vault_path.to_owned(),
        })),
        Err(err) => Err(Error::Message(format!(
            "stat {}: {}",
            vault_path.display(),
            PathError::new("stat", vault_path, err)
        ))),
    }
}

/// Runs on a vault that is already at the current format. It looks for
/// version 1 envelopes that an older binary stranded by writing during
/// a migration, and re-seals any it finds.
///
/// A healthy vault still reports nothing to do, and pays one decrypt
/// for each envelope to prove it.
fn repair_stragglers(
    globals: &Globals,
    vault_path: &Path,
    key: &age::x25519::Identity,
    recipient: &age::x25519::Recipient,
) -> Result<(), Error> {
    let repaired = vault::repair_legacy_envelopes(vault_path, &recipient.to_string(), |row| {
        let address = canonical_address(row.name, row.number);

        match envelope::open(key, &address, row.envelope) {
            Ok(_) => Ok(Resealed::Current),
            // Only a real version 1 frame can be repaired here. A
            // decrypt failure or a real address mismatch is corruption
            // or tampering, and must keep failing loud.
            Err(envelope::Error::Legacy { .. }) => migrate_reseal(key, recipient, &row),
            Err(err) => Err(failure(&err)),
        }
    })
    .map_err(hint::vault)?;

    if repaired == 0 {
        info!("vault is already at the current format, nothing to migrate");

        return Ok(());
    }

    info!(
        "repaired values left in the old format by an older safetybox writing during a migration",
        "count" => repaired,
    );

    print_json(globals, &output(repaired, "repaired"))
}

/// Decrypts one version's legacy envelope and seals the value into the
/// current frame. An env name the new frame cannot carry is cleaned
/// first, with a warning that names the secret. The name that was
/// sealed is handed back, so the vault can make the column agree.
fn migrate_reseal(
    key: &age::x25519::Identity,
    recipient: &age::x25519::Recipient,
    row: &MigrateRow<'_>,
) -> Result<Resealed, ResealFailure> {
    let address = canonical_address(row.name, row.number);

    let value = envelope::open_legacy(key, &address, row.envelope).map_err(|err| failure(&err))?;
    let env_name = frame_safe_env_name(row.env_name);

    if env_name != row.env_name {
        warn!(
            "secret env name had a newline the new format cannot store, re-set it with --env-name if you need a different one",
            "name" => row.name,
            "stored_as" => env_name.as_str(),
        );
    }

    // The expiry is bound exactly as stored. The value wipes itself
    // when this returns.
    let bound = Bound::new(Some(&env_name), Some(row.expires_at));

    let sealed =
        envelope::seal(recipient, &address, &bound, &value).map_err(|err| failure(&err))?;

    Ok(Resealed::Envelope { sealed, env_name })
}

/// An envelope failure with its advice. The envelope error already
/// names the address, and the vault names the secret and version.
///
/// The advice travels beside the message and is added once, at the
/// end of the whole error.
fn failure(err: &envelope::Error) -> ResealFailure {
    ResealFailure {
        message: err.to_string(),
        advice: hint::envelope_advice(err),
    }
}

/// `env_name` without the characters the envelope frame cannot carry,
/// which today is the newline. A vault from before set checked env
/// names could store one with a newline. An env name with a trailing
/// newline, the common case, becomes the name that was meant.
fn frame_safe_env_name(env_name: &str) -> String {
    env_name.replace(['\n', '\r'], "")
}

#[cfg(test)]
mod tests {
    use super::{failure, frame_safe_env_name};
    use crate::cmd::hint;
    use crate::envelope;
    use crate::vault;

    #[test]
    fn advice_for_a_failed_reseal_is_given_once() {
        let key = age::x25519::Identity::generate();
        let err = envelope::open(&key, "api/v1/api/one/1", b"not an envelope")
            .expect_err("a corrupt envelope");

        let failure = failure(&err);

        let message = hint::vault(vault::Error::Reseal {
            version: "api/one version 1".to_owned(),
            reason: failure.message,
            advice: failure.advice,
        })
        .to_string();

        assert!(
            message.starts_with(
                "reseal api/one version 1: open \"api/v1/api/one/1\": envelope decrypt failed: "
            ),
            "{message}"
        );
        assert_eq!(
            message
                .matches("the identity may not match this vault")
                .count(),
            1,
            "{message}"
        );
    }

    #[test]
    fn newlines_leave_an_env_name_and_nothing_else_does() {
        for (stored, want) in [
            ("FAKE_NAME", "FAKE_NAME"),
            ("FAKE_NAME\n", "FAKE_NAME"),
            ("FAKE_NAME\r\n", "FAKE_NAME"),
            ("FAKE\nNAME", "FAKENAME"),
            ("\n", ""),
            ("", ""),
            ("FAKE NAME", "FAKE NAME"),
        ] {
            assert_eq!(frame_safe_env_name(stored), want, "{stored:?}");
        }
    }
}
