//! The SQLite-backed secret store.
//!
//! It stores metadata and sealed envelopes only. Plaintext never enters
//! this module. The vault stores the recipient public key, so the write
//! verbs never need the private identity.

mod migrate;
mod schema;
mod store;
mod types;

pub use migrate::{MigrateRow, ResealFailure, Resealed, migrate, repair_legacy_envelopes};
pub use types::{
    AppendResult, Change, Entry, EntryFilter, Resolved, SealRequest, SecretMeta, SetOptions, State,
    Summary, VersionMeta, canonical_address, is_valid_name,
};

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, OptionalExtension, TransactionBehavior};

use crate::sys::{self, PathError, UNSAFE_BITS};

/// The vault format this build reads and writes. Version 2 seals the
/// env name and expiry into each envelope, so a read can detect an
/// edit to a plaintext column. The SQL schema is unchanged from
/// version 1, so the format version can exceed the number of SQL
/// migrations.
const FORMAT_VERSION: u32 = 2;

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

const META_TABLE: &str = "vault_meta";
const META_FORMAT_VERSION: &str = "format_version";
const META_RECIPIENT: &str = "recipient";

/// How long a statement waits on a lock another process holds.
const BUSY_TIMEOUT: Duration = Duration::from_millis(5000);

/// Why a vault operation failed.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No vault exists at the path.
    #[error("open {}: vault not found", .path.display())]
    NotFound { path: PathBuf },

    /// A create was pointed at an existing vault.
    #[error("create {}: vault already exists", .path.display())]
    Exists { path: PathBuf },

    /// The file exists but has no schema or metadata, usually a
    /// half-created vault left by an init that crashed before its
    /// schema transaction committed.
    #[error("open {}: vault is not initialized or is corrupt", .path.display())]
    Corrupt { path: PathBuf },

    /// The vault was written by an incompatible format version.
    #[error(
        "open {}: found version {found}, want {FORMAT_VERSION}: unsupported vault format version",
        .path.display()
    )]
    FormatVersion { path: PathBuf, found: String },

    /// A timestamp column holds a value no writer produces, such as an
    /// empty string or arbitrary text. An edit to the vault file is the
    /// likely cause. A read fails whole and names the secret and the
    /// column, because corruption must not be quietly tolerated.
    #[error(
        "{subject}: {column} = {}: stored timestamp is not valid, the vault may have been edited",
        crate::quote::quote(.raw)
    )]
    StoredTimeCorrupt {
        /// Which row, such as `secret "api/one"`, with the name quoted.
        subject: String,
        column: &'static str,
        raw: String,
    },

    /// No secret has the name.
    #[error("secret {name}: secret not found")]
    SecretNotFound { name: String },

    /// The secret was soft-deleted.
    #[error("secret {name}: secret deleted")]
    SecretDeleted { name: String },

    /// The secret has no such version. `version` reads `version 2 of
    /// api/one`.
    #[error("{version}: secret version not found")]
    VersionNotFound { version: String },

    /// The version's envelope was erased.
    #[error("{version}: secret version destroyed")]
    VersionDestroyed { version: String },

    /// The write-ahead log could not be truncated, usually because
    /// another process holds a read snapshot.
    #[error("checkpoint wal: wal checkpoint blocked")]
    CheckpointBlocked,

    /// The secret name breaks the name grammar. The name is held
    /// already quoted, because it is whatever was typed.
    #[error("{name}: invalid secret name")]
    InvalidName { name: String },

    /// A commit reported an error after its record may already have
    /// become durable, so whether the transaction landed is unknown. A
    /// failed sync is the usual case. A caller whose cleanup destroys
    /// something must not read this as proof of a rollback.
    #[error("{context}: commit failed with unknown outcome: {}", describe_sqlite(.source))]
    CommitAmbiguous {
        context: &'static str,
        source: rusqlite::Error,
    },

    /// The caller could not re-encrypt a version. `version` reads
    /// `api/one version 2`. `advice` is what to do about it, which the
    /// command line adds to the message.
    #[error("reseal {version}: {reason}")]
    Reseal {
        version: String,
        reason: String,
        advice: Option<String>,
    },

    /// A migration was asked to upgrade a vault that is already at the
    /// current format, so there is nothing to do. A second run after a
    /// crash reaches this cleanly.
    #[error("vault is already at the current format")]
    AlreadyCurrent,

    /// The vault is at a format a migration cannot start from.
    #[error(
        "open {}: found version {found}, only version 1 migrates: unsupported vault format version",
        .path.display()
    )]
    NotMigratable { path: PathBuf, found: String },

    /// The stored recipient is not the identity presented to migrate,
    /// so nothing is re-sealed, the way the read verbs refuse.
    #[error("open {}: vault recipient does not match your identity", .path.display())]
    RecipientMismatch { path: PathBuf },

    /// The caller could not seal the new version.
    #[error("seal {name}: {reason}")]
    Seal { name: String, reason: String },

    #[error("{context}: {source}")]
    File { context: String, source: PathError },

    #[error("{context}: {}", describe_sqlite(.source))]
    Database {
        context: String,
        source: rusqlite::Error,
    },
}

/// An open handle to a vault database.
#[derive(Debug)]
pub struct Vault {
    connection: Connection,
    path: PathBuf,
}

/// Makes a new vault at `path` holding `recipient`. The file is created
/// 0600, with WAL journaling and the version 1 schema. It fails if
/// `path` already exists.
pub fn create(path: &Path, recipient: &str) -> Result<(), Error> {
    let path = sys::clean(path);
    let creating = format!("create {}", path.display());

    match fs::metadata(&path) {
        Ok(_) => return Err(Error::Exists { path }),
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(file_error(&creating, "stat", &path, err)),
    }

    let directory = sys::parent(&path);

    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&directory)
        .map_err(|err| file_error("create vault directory", "mkdir", &directory, err))?;

    // Create the file first so its permissions are 0600 from the first
    // byte. SQLite gives the -wal and -shm siblings the same mode.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|err| file_error(&creating, "open", &path, err))?;

    let initialized = open_connection(&path).and_then(|mut connection| {
        init_schema(&mut connection, recipient)?;

        connection.close().map_err(|(_, err)| Error::Database {
            context: "close new vault".to_owned(),
            source: err,
        })
    });

    if initialized.is_err() {
        remove_files(&path);
    }

    initialized
}

impl Vault {
    /// Opens an existing vault and verifies its format version.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let path = sys::clean(path);
        let opening = format!("open {}", path.display());

        match fs::metadata(&path) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => return Err(Error::NotFound { path }),
            Err(err) => return Err(file_error(&opening, "stat", &path, err)),
        }

        let vault = Self {
            connection: open_connection(&path)?,
            path,
        };

        // A file that opens as SQLite but lacks the metadata table is a
        // half-created or foreign file. That is kept apart from an
        // operational error, such as a locked or unreadable database,
        // which must not be reported as corrupt: the advice for a
        // corrupt vault is to move the file aside.
        if !vault
            .table_exists(META_TABLE)
            .map_err(|err| nest(&opening, err))?
        {
            return Err(Error::Corrupt { path: vault.path });
        }

        // The table exists but its version row is missing, so the
        // metadata is incomplete.
        let Some(found) = vault
            .meta_value(META_FORMAT_VERSION)
            .map_err(|err| nest(&format!("{opening}: read format version"), err))?
        else {
            return Err(Error::Corrupt { path: vault.path });
        };

        if found != FORMAT_VERSION.to_string() {
            return Err(Error::FormatVersion {
                path: vault.path,
                found,
            });
        }

        Ok(vault)
    }

    /// The filesystem path of the open vault.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The stored recipient public key.
    pub fn recipient(&self) -> Result<String, Error> {
        let reading = "read recipient";

        self.meta_value(META_RECIPIENT)
            .map_err(|err| nest(reading, err))?
            .ok_or_else(|| Error::Database {
                context: format!("{reading}: vault_meta[{META_RECIPIENT}]"),
                source: rusqlite::Error::QueryReturnedNoRows,
            })
    }

    /// Reports whether the schema holds a table called `name`.
    fn table_exists(&self, name: &str) -> Result<bool, Error> {
        self.connection
            .query_row(
                "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?1",
                [name],
                |_| Ok(()),
            )
            .optional()
            .map(|found| found.is_some())
            .map_err(|err| Error::Database {
                context: format!("check {name} table"),
                source: err,
            })
    }

    /// One metadata value, or `None` when its row is missing.
    fn meta_value(&self, key: &str) -> Result<Option<String>, Error> {
        self.connection
            .query_row(
                "SELECT value FROM vault_meta WHERE key = ?1",
                [key],
                |row| types::text(row, 0),
            )
            .optional()
            .map_err(|err| Error::Database {
                context: format!("vault_meta[{key}]"),
                source: err,
            })
    }
}

/// Opens the database file at `path` with the connection settings every
/// vault connection carries.
///
/// The path is handed to SQLite as a plain file name, never as a URI.
/// A URI ends the file name at the first `#` and starts its query at
/// the first `?`, so a path holding either would open a different file
/// than the one created here. See [`sqlite_name`].
///
/// `secure_delete` makes SQLite overwrite freed content with zeros
/// instead of leaving it in free pages, so purge and rekey destroy old
/// envelope bytes.
fn open_connection(path: &Path) -> Result<Connection, Error> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;

    let configure = || -> rusqlite::Result<Connection> {
        let connection = Connection::open_with_flags(sqlite_name(path), flags)?;

        connection.busy_timeout(BUSY_TIMEOUT)?;
        connection.pragma_update(None, "journal_mode", "WAL")?;
        connection.pragma_update(None, "foreign_keys", 1)?;
        connection.pragma_update(None, "secure_delete", 1)?;

        Ok(connection)
    };

    configure().map_err(|err| Error::Database {
        context: "open database".to_owned(),
        source: err,
    })
}

/// A database error, worded the way the Go original's driver words
/// one: SQLite's name for the result code, then its detail when it has
/// more to say, then the code. `SQL logic error: no such table: secret
/// (1)` reads the same from both programs.
fn describe_sqlite(err: &rusqlite::Error) -> String {
    let (failure, detail) = match err {
        rusqlite::Error::SqliteFailure(failure, detail) => (failure, detail.as_deref()),
        rusqlite::Error::QueryReturnedNoRows => return "sql: no rows in result set".to_owned(),
        other => return other.to_string(),
    };

    let code = failure.extended_code;

    // SAFETY: sqlite3_errstr takes any integer and returns a pointer
    // to a static, NUL-terminated string that is never freed.
    let name = unsafe { std::ffi::CStr::from_ptr(rusqlite::ffi::sqlite3_errstr(code)) }
        .to_string_lossy()
        .into_owned();

    // The driver marks a lock held by another connection.
    let busy = if code == rusqlite::ffi::SQLITE_BUSY {
        " (SQLITE_BUSY)"
    } else {
        ""
    };

    // A detail that only repeats the name adds nothing. An open
    // failure's detail is the name followed by the path, and the Go
    // original prints the name alone there.
    match detail.filter(|detail| !detail.starts_with(&name)) {
        Some(detail) => format!("{name}: {detail} ({code}){busy}"),
        None => format!("{name} ({code}){busy}"),
    }
}

/// The name SQLite is given for the file at `path`.
///
/// The bundled SQLite reads any name that starts with `file:` as a
/// URI, whatever flags the open passes. A relative path can start that
/// way, and the database would then land in a different file, created
/// with the default mode, while the 0600 file made here stayed empty.
/// A relative path is therefore anchored at `./`, which names the same
/// file and can never be a URI. An absolute path starts with `/`.
fn sqlite_name(path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        Path::new(".").join(path)
    }
}

/// Applies every migration and writes the metadata rows, in one
/// transaction.
fn init_schema(connection: &mut Connection, recipient: &str) -> Result<(), Error> {
    let failed = |context: String| {
        move |err| Error::Database {
            context,
            source: err,
        }
    };

    let transaction = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(failed("begin schema transaction".to_owned()))?;

    for (index, migration) in schema::MIGRATIONS.iter().enumerate() {
        transaction
            .execute_batch(migration)
            .map_err(failed(format!("apply migration {}", index + 1)))?;
    }

    let insert = "INSERT INTO vault_meta (key, value) VALUES (?1, ?2)";

    transaction
        .execute(insert, [META_FORMAT_VERSION, &FORMAT_VERSION.to_string()])
        .map_err(failed("write format version".to_owned()))?;

    transaction
        .execute(insert, [META_RECIPIENT, recipient])
        .map_err(failed("write recipient".to_owned()))?;

    transaction
        .commit()
        .map_err(failed("commit schema".to_owned()))
}

/// One vault-related path whose mode grants group or world access.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoosePermission {
    /// What the path is, such as `vault file`.
    pub label: &'static str,
    pub path: PathBuf,
    /// The mode the path carries now.
    pub mode: u32,
    /// The mode it should carry.
    pub recommend: u32,
}

/// Every vault-related path that grants group or world access: the
/// database file, its directory, and the `-wal` and `-shm` siblings. A
/// path that does not exist is skipped.
///
/// The identity file gates key material and is refused when loose. The
/// vault holds ciphertext and public metadata, so a loose vault is
/// reported, never blocked.
pub fn loose_permissions(path: &Path) -> Vec<LoosePermission> {
    let path = sys::clean(path);

    let targets = [
        ("vault file", path.clone(), FILE_MODE),
        ("vault directory", sys::parent(&path), DIR_MODE),
        (
            "vault write-ahead log",
            sys::sibling(&path, "-wal"),
            FILE_MODE,
        ),
        (
            "vault shared-memory file",
            sys::sibling(&path, "-shm"),
            FILE_MODE,
        ),
    ];

    targets
        .into_iter()
        .filter_map(|(label, path, recommend)| {
            let mode = fs::metadata(&path).ok()?.permissions().mode() & 0o777;

            (mode & UNSAFE_BITS != 0).then_some(LoosePermission {
                label,
                path,
                mode,
                recommend,
            })
        })
        .collect()
}

/// Deletes a vault database and its WAL siblings, best effort. It is
/// for unwinding a vault created earlier in the same invocation, such
/// as after a failed self-test, so a retry does not find a vault in
/// the way. It cannot tell a live vault from a half-created one. The
/// caller owns that judgement.
pub fn remove_files(path: &Path) {
    let _ = fs::remove_file(path);
    let _ = fs::remove_file(sys::sibling(path, "-wal"));
    let _ = fs::remove_file(sys::sibling(path, "-shm"));
}

fn file_error(context: &str, operation: &'static str, path: &Path, source: io::Error) -> Error {
    Error::File {
        context: context.to_owned(),
        source: PathError::new(operation, path, source),
    }
}

/// Puts `context` in front of a database error's own context.
fn nest(context: &str, err: Error) -> Error {
    match err {
        Error::Database {
            context: inner,
            source,
        } => Error::Database {
            context: format!("{context}: {inner}"),
            source,
        },
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use rusqlite::Connection;

    use super::{Error, Vault, create, loose_permissions, remove_files};

    const RECIPIENT: &str = "age1fakefakefakefakefakefakefakefakefakefakefakefakefakefakefake";

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[test]
    fn create_then_open_reads_the_recipient_back() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("data").join("vault.db");

        create(&path, RECIPIENT).expect("create");

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().expect("parent")), 0o700);

        let vault = Vault::open(&path).expect("open");

        assert_eq!(vault.recipient().expect("recipient"), RECIPIENT);
        assert_eq!(vault.path(), path);
    }

    #[test]
    fn create_refuses_an_existing_file_and_leaves_it() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        fs::write(&path, "occupied").expect("write");

        let refused = create(&path, RECIPIENT).expect_err("an existing file");

        assert!(matches!(refused, Error::Exists { .. }));
        assert_eq!(
            refused.to_string(),
            format!("create {}: vault already exists", path.display())
        );
        assert_eq!(fs::read(&path).expect("read"), b"occupied");
    }

    #[test]
    fn open_names_what_is_wrong() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        let missing = Vault::open(&path).expect_err("no vault");
        assert_eq!(
            missing.to_string(),
            format!("open {}: vault not found", path.display())
        );

        fs::write(&path, "").expect("write an empty file");
        let empty = Vault::open(&path).expect_err("an empty file");
        assert!(matches!(empty, Error::Corrupt { .. }), "{empty}");

        fs::write(&path, "this is not a sqlite database").expect("write garbage");
        let garbage = Vault::open(&path).expect_err("a garbage file");
        assert!(
            garbage.to_string().starts_with("open database: "),
            "{garbage}"
        );
        assert!(garbage.to_string().contains("not a database"), "{garbage}");
    }

    #[test]
    fn open_checks_the_format_version() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        create(&path, RECIPIENT).expect("create");

        let edit = |statement: &str| {
            Connection::open(&path)
                .expect("open")
                .execute(statement, [])
                .expect("edit");
        };

        edit("UPDATE vault_meta SET value = '999' WHERE key = 'format_version'");
        let unknown = Vault::open(&path).expect_err("an unknown version");
        assert_eq!(
            unknown.to_string(),
            format!(
                "open {}: found version 999, want 2: unsupported vault format version",
                path.display()
            )
        );

        edit("DELETE FROM vault_meta WHERE key = 'format_version'");
        let incomplete = Vault::open(&path).expect_err("a missing version row");
        assert!(matches!(incomplete, Error::Corrupt { .. }), "{incomplete}");
    }

    #[test]
    fn database_errors_read_like_the_reference() {
        use rusqlite::ffi;

        let failure = |code: i32, detail: Option<&str>| {
            super::describe_sqlite(&rusqlite::Error::SqliteFailure(
                ffi::Error::new(code),
                detail.map(str::to_owned),
            ))
        };

        assert_eq!(
            failure(ffi::SQLITE_NOTADB, Some("file is not a database")),
            "file is not a database (26)"
        );
        assert_eq!(
            failure(
                ffi::SQLITE_CANTOPEN,
                Some("unable to open database file: /fake/path")
            ),
            "unable to open database file (14)"
        );
        assert_eq!(
            failure(ffi::SQLITE_ERROR, Some("no such table: secret")),
            "SQL logic error: no such table: secret (1)"
        );
        assert_eq!(
            failure(ffi::SQLITE_READONLY, None),
            "attempt to write a readonly database (8)"
        );
        assert_eq!(
            failure(ffi::SQLITE_BUSY, Some("database is locked")),
            "database is locked (5) (SQLITE_BUSY)"
        );
        assert_eq!(
            super::describe_sqlite(&rusqlite::Error::QueryReturnedNoRows),
            "sql: no rows in result set"
        );

        // A real failure, through the whole error.
        let connection = Connection::open_in_memory().expect("open");
        let source = connection
            .execute("SELECT * FROM absent", [])
            .expect_err("no such table");

        assert_eq!(
            Error::Database {
                context: "list secrets".to_owned(),
                source,
            }
            .to_string(),
            "list secrets: SQL logic error: no such table: absent (1)"
        );
    }

    #[test]
    fn a_relative_path_can_never_read_as_a_uri() {
        for (path, want) in [
            ("file:v.db", "./file:v.db"),
            ("file:v.db?mode=ro", "./file:v.db?mode=ro"),
            ("vault.db", "./vault.db"),
            ("data/vault.db", "./data/vault.db"),
            ("/abs/file:v.db", "/abs/file:v.db"),
        ] {
            assert_eq!(
                super::sqlite_name(Path::new(path)),
                Path::new(want),
                "{path}"
            );
        }
    }

    // Go: TestSQLiteDSNEscapesURISpecialCharacters
    #[test]
    fn a_path_with_uri_characters_names_the_file_itself() {
        for name in ["my#box", "why?", "100%", "all#of?these%", "%23", "file:x"] {
            let directory = tempfile::tempdir().expect("temp dir");
            let path = directory.path().join(name).join("vault.db");

            create(&path, RECIPIENT).expect("create");

            assert!(fs::metadata(&path).expect("stat").len() > 0, "{name}");
            assert_eq!(
                Vault::open(&path)
                    .expect("open")
                    .recipient()
                    .expect("recipient"),
                RECIPIENT,
                "{name}"
            );

            let entries = fs::read_dir(path.parent().expect("parent"))
                .expect("list")
                .count();

            assert_eq!(
                entries, 1,
                "{name}: the vault directory holds the vault alone"
            );
        }
    }

    #[test]
    fn loose_permissions_reports_each_loose_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("data").join("vault.db");

        create(&path, RECIPIENT).expect("create");
        assert_eq!(loose_permissions(&path), []);

        chmod(&path, 0o644);
        chmod(path.parent().expect("parent"), 0o755);

        let loose = loose_permissions(&path);
        let found: Vec<_> = loose
            .iter()
            .map(|entry| (entry.label, entry.mode, entry.recommend))
            .collect();

        assert_eq!(
            found,
            [
                ("vault file", 0o644, 0o600),
                ("vault directory", 0o755, 0o700)
            ]
        );
    }

    #[test]
    fn remove_files_takes_the_siblings_too() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("vault.db");

        for suffix in ["", "-wal", "-shm"] {
            fs::write(format!("{}{suffix}", path.display()), "x").expect("write");
        }

        remove_files(&path);

        assert_eq!(fs::read_dir(directory.path()).expect("list").count(), 0);
    }
}
