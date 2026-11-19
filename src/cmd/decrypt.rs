//! Unlocking the identity and opening envelopes, shared by every verb
//! that decrypts.

use std::fs;
use std::io::{self, ErrorKind};
use std::path::Path;

use super::cli::Globals;
use super::{Error, hint, open_vault, passphrase, paths};
use crate::envelope::{self, Bound};
use crate::quote::quote;
use crate::secret::Value;
use crate::sys::{self, PathError};
use crate::timestamp::Time;
use crate::vault::{Entry, SecretMeta, VersionMeta, canonical_address};
use crate::{debug, identity, warn};

/// A plaintext column no longer matches the metadata sealed into the
/// newest version's envelope.
const METADATA_TAMPERED: &str = "vault metadata does not match the sealed value";

/// A decrypted secret with its metadata.
pub struct Resolved {
    pub secret: SecretMeta,
    pub version: VersionMeta,
    pub value: Value,
}

/// Fetches, decrypts, and verifies the newest enabled version of
/// `name`. An expired secret still resolves, with a warning.
pub fn resolve_newest(globals: &Globals, name: &str) -> Result<Resolved, Error> {
    let vault = open_vault(globals)?;
    let newest = vault.newest_enabled(name);
    let recipient = vault.recipient();

    // The vault is closed before the passphrase is asked for, so a
    // prompt left waiting holds no database handle.
    drop(vault);

    let newest = newest.map_err(hint::vault)?;
    let recipient = recipient.map_err(|err| hint::vault_in("read stored recipient", err))?;

    debug!(
        "newest enabled version resolved",
        "name" => name,
        "version" => newest.version.number,
    );

    let key = load_identity(globals)?;

    verify_recipient(&recipient, &key)?;

    let address = canonical_address(name, newest.version.number);

    let (value, bound) = envelope::open(&key, &address, &newest.envelope)
        .map_err(|err| Error::Message(format!("open {}: {}", quote(name), hint::envelope(&err))))?;

    verify_bound(
        newest.secret.env_name.as_deref(),
        newest.secret.expires_at,
        &bound,
    )
    .map_err(|detail| {
        Error::Message(format!(
            "verify {}: {METADATA_TAMPERED}: {detail}",
            quote(name)
        ))
    })?;

    if newest.secret.expired(Time::now()) {
        warn_expired(name, newest.secret.expires_at);
    }

    Ok(Resolved {
        secret: newest.secret,
        version: newest.version,
        value,
    })
}

/// Unlocks the identity once and opens every entry's envelope with it,
/// handing `visit` each entry, whether it is expired, and its value.
/// It is the one batch decrypt path, shared by exec and reveal, so a
/// batch derives the key from the passphrase a single time. Nothing is
/// decrypted when the stored recipient does not match the identity.
///
/// `explicit` picks how a metadata mismatch is reported. A secret asked
/// for by name fails loud, as get does. A batch selection skips the one
/// mismatching secret with a warning and delivers the rest. A decrypt
/// or framing failure always fails loud, because that is corruption or
/// a downgrade attempt and not a metadata edit.
///
/// The entries that were skipped are returned. Skipping alone is not
/// safe: a consumer that already holds a value under the same env name
/// would keep it and never learn the real one was withheld. The caller
/// must clear that variable.
pub fn for_each_decrypted(
    globals: &Globals,
    stored_recipient: &str,
    entries: Vec<Entry>,
    explicit: bool,
    mut visit: impl FnMut(&Entry, bool, Value) -> Result<(), Error>,
) -> Result<Vec<Entry>, Error> {
    let key = load_identity(globals)?;

    verify_recipient(stored_recipient, &key)?;

    let now = Time::now();
    let total = entries.len();
    let mut skipped = Vec::new();

    for entry in entries {
        let address = canonical_address(&entry.name, entry.version);

        let (value, bound) = envelope::open(&key, &address, &entry.envelope).map_err(|err| {
            Error::Message(format!(
                "open {}: {}",
                quote(&entry.name),
                hint::envelope(&err)
            ))
        })?;

        if let Err(detail) = verify_bound(entry.env_name.as_deref(), entry.expires_at, &bound) {
            drop(value);

            if explicit {
                return Err(Error::Message(format!(
                    "verify {}: {METADATA_TAMPERED}: {detail}",
                    quote(&entry.name)
                )));
            }

            warn!(
                "secret metadata does not match the sealed value, skipped",
                "name" => entry.name.as_str(),
            );

            skipped.push(entry);

            continue;
        }

        let expired = entry.expired(now);

        if expired {
            warn_expired(&entry.name, entry.expires_at);
        }

        // The value moves into the visitor, which wipes it when done.
        visit(&entry, expired, value)?;
    }

    debug!(
        "batch decrypt finished",
        "entries" => total,
        "skipped" => skipped.len(),
    );

    Ok(skipped)
}

/// Reads the passphrase and decrypts the identity file. The key wipes
/// itself when dropped.
pub fn load_identity(globals: &Globals) -> Result<age::x25519::Identity, Error> {
    let path = paths::identity(globals.identity.as_deref(), &paths::process_env)?;

    complete_interrupted_rekey(&path)?;

    let passphrase = passphrase::read(globals.passphrase_file.as_deref(), "Passphrase: ")?;
    let key = identity::load(&path, &passphrase).map_err(hint::identity)?;

    debug!("identity unlocked", "identity_path" => path.to_string_lossy().as_ref());

    Ok(key)
}

/// Heals the crash window in the identity swap that rekey makes. When
/// the identity file is missing but a staged `.new` sibling exists, a
/// rekey died after moving the old key aside and before promoting the
/// new one. The vault is already on the new key, so the staged file is
/// the live key and is moved into place. Any other state is left alone.
pub fn complete_interrupted_rekey(identity_path: &Path) -> Result<(), Error> {
    let stat_failed = |what: &str, path: &Path, err: io::Error| {
        Error::Message(format!(
            "stat {what} {}: {}",
            path.display(),
            PathError::new("stat", path, err)
        ))
    };

    match fs::metadata(identity_path) {
        Ok(_) => return Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(stat_failed("identity", identity_path, err)),
    }

    let staged = sys::sibling(identity_path, ".new");

    match fs::metadata(&staged) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(stat_failed("staged identity", &staged, err)),
    }

    let Err(err) = fs::rename(&staged, identity_path) else {
        return Ok(());
    };

    // Two invocations can race this heal. If the identity exists now,
    // the other one promoted the staged file first and this one can
    // carry on.
    if fs::metadata(identity_path).is_ok() {
        return Ok(());
    }

    Err(Error::Message(format!(
        "complete interrupted rekey (your new identity is at {}): rename {} {}: {}",
        staged.display(),
        staged.display(),
        identity_path.display(),
        sys::describe(&err)
    )))
}

/// Refuses when the vault's stored recipient does not match the loaded
/// identity. Someone who can write the vault can swap the recipient so
/// later writes seal to their key. The write path cannot catch that,
/// because it never holds the identity. The read path raises the alarm
/// the moment the identity is present, even for old versions that
/// still decrypt under the original key.
pub fn verify_recipient(stored: &str, key: &age::x25519::Identity) -> Result<(), Error> {
    if stored == key.to_public().to_string() {
        return Ok(());
    }

    Err(Error::Message(format!(
        "vault recipient does not match your identity: {}",
        hint::RECIPIENT_MISMATCH_ADVICE
    )))
}

/// Compares the metadata sealed into the envelope with the plaintext
/// columns the vault holds, and says what differs.
///
/// Someone who edits a column without re-sealing the value is caught
/// here, since re-sealing needs the plaintext they do not have. Someone
/// who forges the whole envelope with matching metadata still passes,
/// which is the stated limit of writes that need no key.
///
/// The store maps an empty env name to NULL and never writes a present
/// empty string, and the frame cannot tell one from none. A column
/// that is present but empty is therefore treated as tampering.
pub fn verify_bound(
    env_name: Option<&str>,
    expires_at: Option<Time>,
    bound: &Bound,
) -> Result<(), &'static str> {
    if env_name == Some("") {
        return Err("env name column is present but empty");
    }

    if bound.env_name.as_deref().unwrap_or_default() != env_name.unwrap_or_default() {
        return Err("env name mismatch");
    }

    let sealed = bound.expires_at.as_deref().map(Time::parse_rfc3339);

    match (sealed, expires_at) {
        (None, None) => Ok(()),
        (Some(Some(sealed)), Some(stored)) if sealed == stored => Ok(()),
        _ => Err("expiry mismatch"),
    }
}

/// Warns that `name` is past its expiry. Expiry marks a secret stale.
/// It never blocks a read.
pub fn warn_expired(name: &str, expires_at: Option<Time>) {
    if let Some(expires_at) = expires_at {
        warn!(
            "secret expired",
            "name" => name,
            "expires_at" => expires_at.to_stored(),
        );
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::{complete_interrupted_rekey, verify_bound, verify_recipient};
    use crate::envelope::Bound;
    use crate::timestamp::Time;

    fn time(text: &str) -> Time {
        Time::parse_rfc3339(text).expect("a timestamp")
    }

    #[test]
    fn bound_metadata_must_match_the_columns() {
        let expiry = "2031-01-01T00:00:00Z";
        let both = Bound::new(Some("FAKE_NAME"), Some(expiry));
        let neither = Bound::default();

        assert_eq!(verify_bound(None, None, &neither), Ok(()));
        assert_eq!(
            verify_bound(Some("FAKE_NAME"), Some(time(expiry)), &both),
            Ok(())
        );

        // The same instant under another offset still matches.
        assert_eq!(
            verify_bound(
                Some("FAKE_NAME"),
                Some(time("2031-01-01T01:00:00+01:00")),
                &both
            ),
            Ok(())
        );

        assert_eq!(
            verify_bound(Some(""), None, &neither),
            Err("env name column is present but empty")
        );
        assert_eq!(
            verify_bound(Some("FAKE_OTHER"), Some(time(expiry)), &both),
            Err("env name mismatch")
        );
        assert_eq!(
            verify_bound(None, Some(time(expiry)), &both),
            Err("env name mismatch")
        );
        assert_eq!(
            verify_bound(Some("FAKE_NAME"), None, &both),
            Err("expiry mismatch")
        );
        assert_eq!(
            verify_bound(None, Some(time(expiry)), &neither),
            Err("expiry mismatch")
        );
        assert_eq!(
            verify_bound(Some("FAKE_NAME"), Some(time("2031-01-01T00:00:01Z")), &both),
            Err("expiry mismatch")
        );
        assert_eq!(
            verify_bound(
                None,
                Some(time(expiry)),
                &Bound::new(None, Some("not a time"))
            ),
            Err("expiry mismatch")
        );
    }

    #[test]
    fn a_foreign_recipient_is_refused() {
        let key = age::x25519::Identity::generate();
        let other = age::x25519::Identity::generate();

        verify_recipient(&key.to_public().to_string(), &key).expect("its own recipient");

        let refused =
            verify_recipient(&other.to_public().to_string(), &key).expect_err("another recipient");

        assert!(
            refused
                .to_string()
                .starts_with("vault recipient does not match your identity: ")
        );
    }

    #[test]
    fn a_staged_identity_is_promoted_only_when_the_live_one_is_missing() {
        let directory = tempfile::tempdir().expect("temp dir");
        let live = directory.path().join("identity.age");
        let staged = directory.path().join("identity.age.new");

        // Nothing at all: nothing to heal.
        complete_interrupted_rekey(&live).expect("no files");
        assert!(!live.exists());

        // Both present: the staged file is left alone.
        fs::write(&live, "fake-live").expect("write");
        fs::write(&staged, "fake-staged").expect("write");
        complete_interrupted_rekey(&live).expect("both files");
        assert_eq!(fs::read(&live).expect("read"), b"fake-live");
        assert!(staged.exists());

        // Only the staged file: it becomes the live one.
        fs::remove_file(&live).expect("remove");
        complete_interrupted_rekey(&live).expect("staged only");
        assert_eq!(fs::read(&live).expect("read"), b"fake-staged");
        assert!(!staged.exists());
    }
}
