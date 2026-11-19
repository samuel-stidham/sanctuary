//! The rekey verb: a new identity, and every live version re-encrypted
//! to it.
//!
//! The order of the steps is the safety argument. The new key is on
//! disk before the vault changes, the vault changes in one
//! transaction, and only then do the identity files swap. A crash at
//! any point leaves a key on disk that opens the vault.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use super::cli::Globals;
use super::decrypt::complete_interrupted_rekey;
use super::lifecycle::warn_if_checkpoint_blocked;
use super::{Error, hint, lock, open_vault, passphrase, paths, print_json};
use crate::envelope;
use crate::identity::{self, Passphrase};
use crate::json::Json;
use crate::quote::quote;
use crate::sys::{self, PathError};
use crate::vault::{self, ResealFailure, canonical_address};

pub fn run(globals: &Globals) -> Result<(), Error> {
    let identity_path = paths::identity(globals.identity.as_deref(), &paths::process_env)?;

    // Serialize against other runs that rewrite the identity, before
    // the heal and the load. Without this, a second rekey deletes the
    // staged key of this run while it re-seals, and the vault commits
    // to a key that no longer exists anywhere on disk.
    let _lock = lock::acquire_identity(&identity_path)?;

    // Heal an earlier rekey that crashed in the middle of its swap
    // first, so the load below sees a real identity file.
    complete_interrupted_rekey(&identity_path)?;

    let passphrase = passphrase::read(globals.passphrase_file.as_deref(), "Passphrase: ")?;
    let old_key = identity::load(&identity_path, &passphrase).map_err(hint::identity)?;
    let staged_path = sys::sibling(&identity_path, ".new");

    // Touch nothing unless the vault really is encrypted to the loaded
    // identity. A rekey that committed the vault and crashed before
    // the swap leaves the old key in place, loading cleanly, while the
    // only key that reads the vault sits in the staged file. Deleting
    // that file as stale would destroy every secret for good.
    ensure_vault_on_identity(globals, &old_key, &identity_path, &staged_path)?;

    let new_key = age::x25519::Identity::generate();

    // The new identity is written beside the old one before the vault
    // transaction, so a crash can never leave re-encrypted envelopes
    // without their key on disk.
    stage_new_identity(&staged_path, &new_key, &passphrase)?;

    let count = rekey_vault(globals, &old_key, &new_key)
        .map_err(|failure| clean_up_failed_rekey(failure, &identity_path, &staged_path))?;

    swap_identity_files(&identity_path, &staged_path)?;

    let backup_path = sys::sibling(&identity_path, ".bak");

    print_json(
        globals,
        &Json::Object(vec![
            ("recipient", new_key.to_public().to_string().into()),
            ("rekeyedVersions", count.into()),
            (
                "backupIdentity",
                backup_path.to_string_lossy().into_owned().into(),
            ),
        ]),
    )
}

/// How the vault half of a rekey failed.
#[derive(Debug)]
enum Failure {
    /// The failure came before the commit, so the vault is unchanged.
    Unchanged(Error),

    /// The commit reported an error after its record may already have
    /// become durable, so whether the vault changed is unknown.
    Ambiguous(Error),
}

/// Decides what a failed rekey leaves on disk. A failure before the
/// commit leaves the vault unchanged, so the staged key is removed to
/// keep a retry clean. A commit that errored may still have landed. In
/// that case the staged key may be the only key able to read the
/// vault, so it survives, and the error says to test which key opens
/// the vault before deleting either.
fn clean_up_failed_rekey(failure: Failure, identity_path: &Path, staged_path: &Path) -> Error {
    match failure {
        Failure::Ambiguous(err) => Error::Message(format!(
            "{err}: the vault may or may not be rekeyed: keep both {} and {}, and test which \
             key opens the vault before deleting either",
            identity_path.display(),
            staged_path.display()
        )),
        Failure::Unchanged(err) => {
            let _ = fs::remove_file(staged_path);

            err
        }
    }
}

/// Checks that the vault's stored recipient matches the loaded
/// identity, before rekey stages or removes anything. A clean identity
/// load only proves the passphrase. It does not prove the vault is on
/// that key.
fn ensure_vault_on_identity(
    globals: &Globals,
    old_key: &age::x25519::Identity,
    identity_path: &Path,
    staged_path: &Path,
) -> Result<(), Error> {
    let vault = open_vault(globals)?;
    let stored = vault.recipient();

    drop(vault);

    let stored = stored.map_err(|err| hint::vault_in("read stored recipient", err))?;

    if stored == old_key.to_public().to_string() {
        return Ok(());
    }

    let identity = identity_path.display();
    let staged = staged_path.display();

    Err(Error::Message(match fs::metadata(staged_path) {
        Ok(_) => format!(
            "the vault is not encrypted to the identity at {identity}: a previous rekey \
             likely crashed after re-encrypting the vault, and {staged} is the live key: back \
             it up, then move it to {identity} and retry"
        ),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            format!("the vault is not encrypted to the identity at {identity}: refusing to rekey")
        }
        // A staged key that cannot even be looked at must not be
        // reported as absent. The refusal names the real problem.
        Err(err) => format!(
            "stat staged identity {staged}: {}",
            PathError::new("stat", staged_path, err)
        ),
    }))
}

/// Writes the new identity to its staged file, before the vault
/// transaction. A staged file left by an earlier crashed rekey is
/// removed first. The vault was just proved to be on the loaded key,
/// so that file is a leftover and not a live key.
fn stage_new_identity(
    staged_path: &Path,
    new_key: &age::x25519::Identity,
    passphrase: &Passphrase,
) -> Result<(), Error> {
    match fs::remove_file(staged_path) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        // A failure to remove is reported plainly, so it does not come
        // back as a confusing "already exists" from the write.
        Err(err) => {
            return Err(Error::Message(format!(
                "remove stale staged identity {}: {}",
                staged_path.display(),
                PathError::new("remove", staged_path, err)
            )));
        }
    }

    identity::write(staged_path, new_key, passphrase).map_err(hint::identity)
}

/// Re-encrypts every live version from `old_key` to `new_key` and
/// stores the new recipient, in one transaction.
fn rekey_vault(
    globals: &Globals,
    old_key: &age::x25519::Identity,
    new_key: &age::x25519::Identity,
) -> Result<i64, Failure> {
    let mut vault = open_vault(globals).map_err(Failure::Unchanged)?;
    let recipient = new_key.to_public();

    let count = vault
        .rekey(&recipient.to_string(), |name, number, blob| {
            let address = canonical_address(name, number);

            let (value, bound) =
                envelope::open(old_key, &address, blob).map_err(|err| ResealFailure {
                    message: format!("open {}: {err}", quote(&address)),
                    advice: hint::envelope_advice(&err),
                })?;

            // Each version keeps its bound metadata through the
            // re-seal, so the env name and expiry stay bound to it.
            // The value is wiped as soon as it is sealed again, so a
            // rekey never holds every plaintext at once.
            envelope::seal(&recipient, &address, &bound, &value).map_err(|err| ResealFailure {
                message: format!("reseal {address}: {err}"),
                advice: None,
            })
        })
        .map_err(|err| {
            let ambiguous = matches!(err, vault::Error::CommitAmbiguous { .. });
            let err = hint::vault(err);

            if ambiguous {
                Failure::Ambiguous(err)
            } else {
                Failure::Unchanged(err)
            }
        })?;

    warn_if_checkpoint_blocked(&vault);

    Ok(count)
}

/// Moves the old identity to its backup and the staged identity into
/// place. The vault is already rekeyed here, so a failure says exactly
/// where the new identity is.
fn swap_identity_files(identity_path: &Path, staged_path: &Path) -> Result<(), Error> {
    let backup_path = sys::sibling(identity_path, ".bak");
    let swap_failed = |reason: String| {
        Error::Message(format!(
            "vault rekeyed but identity swap failed, your NEW identity is at {}: {reason}",
            staged_path.display()
        ))
    };

    fs::rename(identity_path, &backup_path)
        .map_err(|err| swap_failed(rename_failed(identity_path, &backup_path, &err)))?;

    promote_staged_identity(staged_path, identity_path).map_err(swap_failed)?;

    // Sync the directory so both renames are durable. Without it a
    // power loss after rekey reports success could undo the swap and
    // leave the old key in place with the vault on the new one. The
    // swap has happened, so a sync failure must say so.
    identity::sync_directory(&sys::parent(identity_path)).map_err(|err| {
        Error::Message(format!(
            "rekey complete and the new identity is in place, but the swap is not yet durable: \
             {err}"
        ))
    })
}

/// Renames the staged key into place. A read verb heals a missing
/// identity by promoting the staged key without taking the identity
/// lock, so one can win this rename between the two steps of the swap.
/// The staged file is then gone and the identity is in place, which is
/// the swap finished and not a failure.
fn promote_staged_identity(staged_path: &Path, identity_path: &Path) -> Result<(), String> {
    let Err(err) = fs::rename(staged_path, identity_path) else {
        return Ok(());
    };

    if err.kind() == ErrorKind::NotFound && fs::metadata(identity_path).is_ok() {
        return Ok(());
    }

    Err(format!(
        "promote staged identity: {}",
        rename_failed(staged_path, identity_path, &err)
    ))
}

fn rename_failed(from: &Path, to: &Path, err: &io::Error) -> String {
    format!(
        "rename {} {}: {}",
        from.display(),
        to.display(),
        sys::describe(err)
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{Failure, clean_up_failed_rekey, promote_staged_identity};
    use crate::cmd::Error;

    // Go: TestFailedRekeyKeepsStagedKeyOnAmbiguousCommit
    //
    // A commit that errored may still have landed, so the staged key
    // may be the only key able to read the vault. It must survive.
    #[test]
    fn failed_rekey_keeps_staged_key_on_ambiguous_commit() {
        let directory = tempfile::tempdir().expect("temp dir");
        let staged = directory.path().join("identity.age.new");

        fs::write(&staged, "fake-staged-key-not-real").expect("write");

        let failure = Failure::Ambiguous(Error::Message(
            "commit rekey: commit failed with unknown outcome".to_owned(),
        ));

        let err = clean_up_failed_rekey(failure, &directory.path().join("identity.age"), &staged);

        assert!(
            err.to_string().contains("test which key opens the vault"),
            "{err}"
        );
        assert!(
            staged.exists(),
            "an ambiguous commit must not delete the staged key"
        );
    }

    // The other half: a failure before the commit leaves the vault
    // unchanged, so the staged key is removed to keep a retry clean.
    #[test]
    fn failed_rekey_removes_staged_key_on_pre_commit_error() {
        let directory = tempfile::tempdir().expect("temp dir");
        let staged = directory.path().join("identity.age.new");

        fs::write(&staged, "fake-staged-key-not-real").expect("write");

        let failure = Failure::Unchanged(Error::Message("reseal failed".to_owned()));
        let err = clean_up_failed_rekey(failure, &directory.path().join("identity.age"), &staged);

        assert_eq!(err.to_string(), "reseal failed");
        assert!(
            !staged.exists(),
            "a pre-commit failure must remove the staged key"
        );
    }

    // Go: TestPromoteStagedIdentityToleratesCompletedHeal
    //
    // A read verb's heal can promote the staged key between the two
    // renames of the swap. A missing staged file with the identity in
    // place is that heal having finished the swap, not a failure.
    #[test]
    fn promote_staged_identity_tolerates_completed_heal() {
        let directory = tempfile::tempdir().expect("temp dir");
        let staged = directory.path().join("identity.age.new");
        let target = directory.path().join("identity.age");

        // Neither file exists.
        let refused = promote_staged_identity(&staged, &target).expect_err("nothing to promote");

        assert_eq!(
            refused,
            format!(
                "promote staged identity: rename {} {}: no such file or directory",
                staged.display(),
                target.display()
            )
        );

        // The staged key is renamed into place.
        fs::write(&staged, "fake-staged-key-not-real").expect("write");
        promote_staged_identity(&staged, &target).expect("promote");
        assert!(target.exists());
        assert!(!staged.exists());

        // A heal already promoted the key.
        promote_staged_identity(&staged, &target).expect("already promoted");
        assert!(target.exists());
    }
}
