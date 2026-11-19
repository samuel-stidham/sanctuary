//! The format migration: every envelope re-sealed into the current
//! frame, in place.
//!
//! Sealing is the caller's, as everywhere in this module. The vault
//! hands over one envelope at a time with the columns to bind into its
//! new frame, and stores what comes back.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};

use super::types::{State, optional_text, shown_name, text};
use super::{
    Error, FORMAT_VERSION, META_FORMAT_VERSION, META_RECIPIENT, META_TABLE, Vault, file_error,
    nest, open_connection,
};
use crate::sys;

/// One version handed to the caller to re-seal, with the metadata to
/// bind into its new frame. An empty env name or expiry means the
/// secret carries none.
#[derive(Debug)]
pub struct MigrateRow<'a> {
    pub name: &'a str,
    pub number: i64,
    pub env_name: &'a str,
    pub expires_at: &'a str,
    pub envelope: &'a [u8],
}

/// What the caller made of one version.
#[derive(Debug)]
pub enum Resealed {
    /// The new envelope, and the env name that was sealed into it. The
    /// name differs from the one handed over when the old one held a
    /// character the new frame cannot store.
    Envelope { sealed: Vec<u8>, env_name: String },

    /// The envelope is already in the current format and needs no
    /// work.
    Current,
}

/// Why the caller could not re-seal a version.
#[derive(Debug)]
pub struct ResealFailure {
    pub message: String,
    /// What to do about it, when there is something to do.
    pub advice: Option<String>,
}

/// The rows a migration works through.
struct Version {
    id: i64,
    name: String,
    number: i64,
    env_name: String,
    expires_at: String,
}

/// Upgrades the format 1 vault at `path` to the current format in
/// place. Every envelope that still exists is re-sealed through
/// `reseal`, then the format version is set. It all happens in one
/// transaction, so a failure leaves the format 1 vault intact.
///
/// It returns how many envelopes were re-sealed. A vault that is
/// already current is [`Error::AlreadyCurrent`], so a second run after
/// a crash is safe. A stored recipient other than `expected_recipient`
/// is refused before anything is re-sealed.
pub fn migrate(
    path: &Path,
    expected_recipient: &str,
    reseal: impl FnMut(MigrateRow<'_>) -> Result<Resealed, ResealFailure>,
) -> Result<i64, Error> {
    let path = sys::clean(path);

    match fs::metadata(&path) {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => return Err(Error::NotFound { path }),
        Err(err) => {
            return Err(file_error(
                &format!("open {}", path.display()),
                "stat",
                &path,
                err,
            ));
        }
    }

    let mut vault = Vault {
        connection: open_connection(&path)?,
        path,
    };

    check_migratable(&vault, expected_recipient)?;

    let count = reseal_for_migration(&mut vault, reseal)?;

    // Flush the log so the old frames do not survive in it. Best
    // effort, as after purge and rekey.
    let _ = vault.checkpoint();

    Ok(count)
}

/// Looks through a vault that is already at the current format and
/// re-seals any version 1 envelope it still holds.
///
/// An older binary racing a migration can strand such a row. It checks
/// the format only when it opens the vault and takes no part in the
/// migrate lock, so a write that began during the migration commits a
/// version 1 frame the moment the migration lands. Every later read of
/// that version is refused.
///
/// `reseal` sees every envelope that still exists and answers
/// [`Resealed::Current`] for one already in the current format. The
/// count returned is how many were repaired, which is zero on a
/// healthy vault.
pub fn repair_legacy_envelopes(
    path: &Path,
    expected_recipient: &str,
    reseal: impl FnMut(MigrateRow<'_>) -> Result<Resealed, ResealFailure>,
) -> Result<i64, Error> {
    let path = sys::clean(path);

    let mut vault = Vault {
        connection: open_connection(&path)?,
        path,
    };

    check_recipient(&vault, expected_recipient)?;

    let count = reseal_stragglers(&mut vault, reseal)?;

    if count > 0 {
        // Keep the old frames out of the log, as a migration does.
        let _ = vault.checkpoint();
    }

    Ok(count)
}

/// Confirms the vault is a real one at format version 1, encrypted to
/// `expected_recipient`.
fn check_migratable(vault: &Vault, expected_recipient: &str) -> Result<(), Error> {
    let opening = format!("open {}", vault.path.display());
    let corrupt = || Error::Corrupt {
        path: vault.path.clone(),
    };

    if !vault
        .table_exists(META_TABLE)
        .map_err(|err| nest(&opening, err))?
    {
        return Err(corrupt());
    }

    let found = vault.meta_value(META_FORMAT_VERSION)?.ok_or_else(corrupt)?;

    if found == FORMAT_VERSION.to_string() {
        return Err(Error::AlreadyCurrent);
    }

    if found != "1" {
        return Err(Error::NotMigratable {
            path: vault.path.clone(),
            found,
        });
    }

    check_recipient(vault, expected_recipient)
}

/// Refuses a vault whose stored recipient is not the identity that was
/// presented. Every other verb that holds the identity makes this
/// check. Without it a migration would re-seal every envelope of a
/// vault whose recipient was swapped.
fn check_recipient(vault: &Vault, expected_recipient: &str) -> Result<(), Error> {
    let stored = vault
        .meta_value(META_RECIPIENT)?
        .ok_or_else(|| Error::Corrupt {
            path: vault.path.clone(),
        })?;

    if stored != expected_recipient {
        return Err(Error::RecipientMismatch {
            path: vault.path.clone(),
        });
    }

    Ok(())
}

fn database(context: impl Into<String>) -> impl FnOnce(rusqlite::Error) -> Error {
    let context = context.into();

    move |source| Error::Database { context, source }
}

/// Re-seals every envelope and sets the format version, in one
/// transaction.
fn reseal_for_migration(
    vault: &mut Vault,
    mut reseal: impl FnMut(MigrateRow<'_>) -> Result<Resealed, ResealFailure>,
) -> Result<i64, Error> {
    let path = vault.path.clone();

    let transaction = vault
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database("begin migrate transaction"))?;

    // Read the format again inside the write transaction. The earlier
    // check ran before this lock was held, so a second migration can
    // pass it and then queue here behind the first. Without this read
    // the loser would re-seal the winner's new frames and fail with a
    // confusing mismatch. The transaction takes the write lock when it
    // begins, so this read sees the winner's commit.
    ensure_format_one(&transaction, &path)?;

    let versions = collect_versions(&transaction)?;

    for version in &versions {
        if !reseal_one(&transaction, &mut reseal, version)? {
            return Err(Error::Reseal {
                version: format!("{} version {}", shown_name(&version.name), version.number),
                reason: "envelope is already in the current format".to_owned(),
                advice: None,
            });
        }
    }

    transaction
        .execute(
            "UPDATE vault_meta SET value = ?1 WHERE key = ?2",
            params![FORMAT_VERSION.to_string(), META_FORMAT_VERSION],
        )
        .map_err(database("set format version"))?;

    // An ambiguous commit needs no marker here, unlike in rekey. A
    // second run after a false failure lands on the already-current
    // path and destroys nothing.
    transaction.commit().map_err(database("commit migrate"))?;

    Ok(i64::try_from(versions.len()).unwrap_or(i64::MAX))
}

/// Re-seals every legacy envelope found in a vault that is already
/// current, in one transaction. A vault with none commits nothing.
fn reseal_stragglers(
    vault: &mut Vault,
    mut reseal: impl FnMut(MigrateRow<'_>) -> Result<Resealed, ResealFailure>,
) -> Result<i64, Error> {
    let transaction = vault
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(database("begin repair transaction"))?;

    let versions = collect_versions(&transaction)?;
    let mut count = 0_i64;

    for version in &versions {
        // The common case by far is a row that is already current.
        if reseal_one(&transaction, &mut reseal, version)? {
            count += 1;
        }
    }

    if count == 0 {
        return Ok(0);
    }

    transaction.commit().map_err(database("commit repair"))?;

    Ok(count)
}

/// Re-seals one version and stores it. It reports whether anything was
/// stored: a version that is already current is left alone.
fn reseal_one(
    transaction: &Transaction<'_>,
    reseal: &mut impl FnMut(MigrateRow<'_>) -> Result<Resealed, ResealFailure>,
    version: &Version,
) -> Result<bool, Error> {
    let shown = format!("{} version {}", shown_name(&version.name), version.number);

    let envelope: Vec<u8> = transaction
        .query_row(
            "SELECT envelope FROM secret_version WHERE id = ?1",
            [version.id],
            |row| row.get(0),
        )
        .map_err(database(format!("read {shown}")))?;

    let resealed = reseal(MigrateRow {
        name: &version.name,
        number: version.number,
        env_name: &version.env_name,
        expires_at: &version.expires_at,
        envelope: &envelope,
    })
    .map_err(|failure| Error::Reseal {
        version: shown.clone(),
        reason: failure.message,
        advice: failure.advice,
    })?;

    let Resealed::Envelope { sealed, env_name } = resealed else {
        return Ok(false);
    };

    if env_name != version.env_name {
        // The old env name held a character the new frame cannot
        // store, so the caller cleaned it. The column must follow the
        // sealed value, or every later read would be refused. An empty
        // result becomes NULL, since no row holds a present empty env
        // name.
        let column = Some(env_name.as_str()).filter(|name| !name.is_empty());

        transaction
            .execute(
                "UPDATE secret SET env_name = ?1 WHERE name = ?2",
                params![column, version.name],
            )
            .map_err(database(format!(
                "reconcile env name for {}",
                shown_name(&version.name)
            )))?;
    }

    transaction
        .execute(
            "UPDATE secret_version SET envelope = ?1 WHERE id = ?2",
            params![sealed, version.id],
        )
        .map_err(database(format!("store resealed {shown}")))?;

    Ok(true)
}

/// Checks the format version inside the migration transaction. A
/// concurrent migration may have upgraded the vault already, and the
/// loser then reports that cleanly.
fn ensure_format_one(connection: &Connection, path: &Path) -> Result<(), Error> {
    let found: Option<String> = connection
        .query_row(
            "SELECT value FROM vault_meta WHERE key = ?1",
            [META_FORMAT_VERSION],
            |row| text(row, 0),
        )
        .optional()
        .map_err(database("read format version in transaction"))?;

    match found.as_deref() {
        Some("1") => Ok(()),
        Some(found) if found == FORMAT_VERSION.to_string() => Err(Error::AlreadyCurrent),
        Some(found) => Err(Error::NotMigratable {
            path: path.to_owned(),
            found: found.to_owned(),
        }),
        None => Err(Error::Database {
            context: "read format version in transaction".to_owned(),
            source: rusqlite::Error::QueryReturnedNoRows,
        }),
    }
}

/// Every version that still has an envelope, with its secret's env
/// name and expiry as stored. The envelope itself is fetched later,
/// one row at a time.
fn collect_versions(connection: &Connection) -> Result<Vec<Version>, Error> {
    let mut statement = connection
        .prepare(
            "SELECT sv.id, s.name, sv.version_number, s.env_name, s.expires_at
               FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
              WHERE sv.state != ?1 AND sv.envelope IS NOT NULL
              ORDER BY s.name, sv.version_number",
        )
        .map_err(database("collect versions to migrate"))?;

    let rows = statement
        .query_map([State::Destroyed.as_str()], |row| {
            Ok(Version {
                id: row.get(0)?,
                name: text(row, 1)?,
                number: row.get(2)?,
                env_name: optional_text(row, 3)?.unwrap_or_default(),
                expires_at: optional_text(row, 4)?.unwrap_or_default(),
            })
        })
        .map_err(database("collect versions to migrate"))?;

    rows.collect::<Result<_, _>>()
        .map_err(database("scan version to migrate"))
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use rusqlite::Connection;

    use super::{MigrateRow, ResealFailure, Resealed, migrate, repair_legacy_envelopes};
    use crate::vault::{Error, SetOptions, Vault, create};

    const FAKE_RECIPIENT: &str = "age1fakerecipientnotreal";

    fn stamp_format(path: &Path, version: &str) {
        Connection::open(path)
            .expect("open")
            .execute(
                "UPDATE vault_meta SET value = ?1 WHERE key = 'format_version'",
                [version],
            )
            .expect("stamp");
    }

    /// A format 1 vault holding one version whose envelope is a fake
    /// legacy frame. No test here decrypts it.
    fn legacy_vault(path: &Path) {
        create(path, FAKE_RECIPIENT).expect("create");

        Vault::open(path)
            .expect("open")
            .append_version("api/one", &SetOptions::default(), |request| {
                Ok(format!("legacy:{}", request.address).into_bytes())
            })
            .expect("append");

        stamp_format(path, "1");
    }

    fn reseal(row: MigrateRow<'_>) -> Result<Resealed, ResealFailure> {
        let mut sealed = b"resealed:".to_vec();

        sealed.extend_from_slice(row.envelope);

        Ok(Resealed::Envelope {
            sealed,
            env_name: row.env_name.to_owned(),
        })
    }

    fn envelope(path: &Path) -> Vec<u8> {
        Connection::open(path)
            .expect("open")
            .query_row("SELECT envelope FROM secret_version", [], |row| row.get(0))
            .expect("envelope")
    }

    // Go: TestConcurrentMigrateLoserGetsAlreadyCurrent
    //
    // Two concurrent runs both pass the format check made before the
    // transaction, then queue on the write lock. Without the check
    // made inside the transaction, the loser would re-seal the
    // winner's new frames. With it, the loser reports a clean no-op,
    // and the vault ends at the current format with the secret intact.
    #[test]
    fn concurrent_migrate_loser_gets_already_current() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        legacy_vault(&path);

        // The winner signals once it is inside its write transaction,
        // then holds the lock, so the loser starts and waits on it.
        let (started, inside) = mpsc::channel();

        let winner = thread::spawn({
            let path = path.clone();

            move || {
                migrate(&path, FAKE_RECIPIENT, |row| {
                    let _ = started.send(());

                    thread::sleep(Duration::from_millis(300));

                    reseal(row)
                })
            }
        });

        inside.recv().expect("the winner starts");

        let loser = migrate(&path, FAKE_RECIPIENT, reseal);

        assert_eq!(winner.join().expect("join").expect("the winner"), 1);
        assert!(
            matches!(loser, Err(Error::AlreadyCurrent)),
            "the loser must report a clean no-op: {loser:?}"
        );

        Vault::open(&path).expect("the vault is at the current format");
        assert_eq!(
            envelope(&path),
            b"resealed:legacy:api/v1/api/one/1",
            "the winner's frame is sealed once"
        );
    }

    #[test]
    fn migrate_checks_the_vault_before_it_reseals() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");
        let never = |_: MigrateRow<'_>| -> Result<Resealed, ResealFailure> {
            panic!("nothing may be re-sealed")
        };

        assert!(matches!(
            migrate(&path, FAKE_RECIPIENT, never),
            Err(Error::NotFound { .. })
        ));

        legacy_vault(&path);

        assert_eq!(
            migrate(&path, "age1fakeotherrecipient", never)
                .expect_err("another recipient")
                .to_string(),
            format!(
                "open {}: vault recipient does not match your identity",
                path.display()
            )
        );

        stamp_format(&path, "7");
        assert_eq!(
            migrate(&path, FAKE_RECIPIENT, never)
                .expect_err("a newer format")
                .to_string(),
            format!(
                "open {}: found version 7, only version 1 migrates: unsupported vault format \
                 version",
                path.display()
            )
        );

        stamp_format(&path, "2");
        assert!(matches!(
            migrate(&path, FAKE_RECIPIENT, never),
            Err(Error::AlreadyCurrent)
        ));
    }

    #[test]
    fn a_failed_reseal_leaves_the_old_format_in_place() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        legacy_vault(&path);

        let refused = migrate(&path, FAKE_RECIPIENT, |_| {
            Err(ResealFailure {
                message: "fake failure".to_owned(),
                advice: None,
            })
        })
        .expect_err("a failed reseal");

        assert_eq!(
            refused.to_string(),
            "reseal api/one version 1: fake failure"
        );
        assert_eq!(envelope(&path), b"legacy:api/v1/api/one/1");
        assert!(matches!(
            Vault::open(&path),
            Err(Error::FormatVersion { .. })
        ));
    }

    #[test]
    fn a_cleaned_env_name_is_written_back() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        legacy_vault(&path);

        Connection::open(&path)
            .expect("open")
            .execute("UPDATE secret SET env_name = 'FAKE_NAME\n'", [])
            .expect("edit");

        let count = migrate(&path, FAKE_RECIPIENT, |row| {
            assert_eq!(row.env_name, "FAKE_NAME\n");

            Ok(Resealed::Envelope {
                sealed: b"fake-sealed".to_vec(),
                env_name: "FAKE_NAME".to_owned(),
            })
        })
        .expect("migrate");

        assert_eq!(count, 1);

        let (secret, _) = Vault::open(&path)
            .expect("open")
            .meta("api/one")
            .expect("meta");

        assert_eq!(secret.env_name.as_deref(), Some("FAKE_NAME"));
    }

    #[test]
    fn repair_stores_only_what_was_resealed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        legacy_vault(&path);
        stamp_format(&path, "2");

        let untouched = repair_legacy_envelopes(&path, FAKE_RECIPIENT, |_| Ok(Resealed::Current))
            .expect("nothing to repair");

        assert_eq!(untouched, 0);
        assert_eq!(envelope(&path), b"legacy:api/v1/api/one/1");

        assert_eq!(
            repair_legacy_envelopes(&path, FAKE_RECIPIENT, reseal).expect("repair"),
            1
        );
        assert_eq!(envelope(&path), b"resealed:legacy:api/v1/api/one/1");
    }
}
