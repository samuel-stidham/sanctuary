//! The vault file. Ports `internal/vault/vault_test.go` and the
//! observable half of `internal/vault/dsn_internal_test.go` through the
//! database the binary creates and the databases it refuses.

use std::fs;

use rusqlite::Connection;

use crate::support::{
    Fixture, PASSPHRASE, VALUE_ONE, arg, chmod, mkdir, mode_of, msg, run, sandboxed, sibling,
    write_file,
};

/// The schema the reference implementation creates, statement for
/// statement. A port that creates anything else is not format-compatible.
const SCHEMA: [(&str, &str); 4] = [
    (
        "vault_meta",
        "CREATE TABLE vault_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT",
    ),
    (
        "secret",
        "CREATE TABLE secret (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL UNIQUE,
    env_name   TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted_at TEXT,
    expires_at TEXT
) STRICT",
    ),
    (
        "secret_version",
        "CREATE TABLE secret_version (
    id             INTEGER PRIMARY KEY,
    secret_id      INTEGER NOT NULL REFERENCES secret (id),
    version_number INTEGER NOT NULL,
    state          TEXT NOT NULL CHECK (state IN ('enabled', 'disabled', 'destroyed')),
    envelope       BLOB,
    created_at     TEXT NOT NULL,
    UNIQUE (secret_id, version_number)
) STRICT",
    ),
    (
        "secret_version_lookup",
        "CREATE INDEX secret_version_lookup
    ON secret_version (secret_id, state, version_number)",
    ),
];

// Go: TestCreateAndOpen
#[test]
fn create_and_open() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    let recipient = fixture.recipient();
    assert!(recipient.starts_with("age1"));

    let format_version: String = fixture
        .db()
        .query_row(
            "SELECT value FROM vault_meta WHERE key = 'format_version'",
            [],
            |row| row.get(0),
        )
        .expect("read format version");

    assert_eq!(format_version, "2");

    // The vault holds exactly its two metadata rows and nothing else.
    let meta_rows: i64 = fixture
        .db()
        .query_row("SELECT COUNT(*) FROM vault_meta", [], |row| row.get(0))
        .expect("count metadata rows");

    assert_eq!(meta_rows, 2);
    assert_eq!(fixture.ok("", &["list", "--json"]).stdout, "[]\n");
}

// Go: TestCreateSetsRestrictivePermissions
#[test]
fn create_sets_restrictive_permissions() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    assert_eq!(mode_of(&fixture.vault), 0o600, "vault file must be 0600");
    assert_eq!(
        mode_of(fixture.vault.parent().expect("vault dir")),
        0o700,
        "vault directory must be 0700"
    );
}

// Go: TestWALSiblingInheritsPermissions
//
// The -wal and -shm siblings must be 0600 like the main database, not
// left at the process umask default. The binary closes the vault before
// it exits, which removes them, so a second connection keeps them alive
// for inspection. SQLite gives them the database file's mode, whichever
// connection creates them.
#[test]
fn wal_sibling_inherits_permissions() {
    let fixture = Fixture::new();

    let reader = fixture.db();
    let count: i64 = reader
        .query_row("SELECT COUNT(*) FROM secret", [], |row| row.get(0))
        .expect("open a read connection");

    assert_eq!(count, 0);

    fixture.set("wal/probe", VALUE_ONE, &[]);

    let wal = sibling(&fixture.vault, "-wal");
    let shm = sibling(&fixture.vault, "-shm");

    assert!(wal.exists(), "a write must create the -wal sibling");
    assert_eq!(mode_of(&wal), 0o600, "-wal sibling must be 0600");
    assert_eq!(mode_of(&shm), 0o600, "-shm sibling must be 0600");

    drop(reader);
}

// Go: TestCreateRefusesExistingVault
//
// init refuses an existing vault before it writes an identity.
#[test]
fn create_refuses_existing_vault() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.vault).expect("read vault");

    fs::remove_file(&fixture.identity).expect("remove identity");

    fixture
        .fail("", &["init"])
        .assert_stderr(msg::VAULT_EXISTS)
        .assert_stderr("half-created husk");

    assert_eq!(fs::read(&fixture.vault).expect("read vault"), before);
    assert!(
        !fixture.identity.exists(),
        "the identity written for this attempt is removed"
    );
}

// Go: TestOpenMissingVault
#[test]
fn open_missing_vault() {
    let fixture = Fixture::empty();

    for verb in [
        &["list"][..],
        &["stale"],
        &["show", "api/one"],
        &["get", "api/one"],
        &["reveal", "api/one"],
        &["reveal", "--env"],
        &["exec", "--", "true"],
        &["disable", "api/one", "1"],
        &["delete", "api/one"],
        &["purge", "api/one", "--yes"],
    ] {
        fixture
            .fail("", verb)
            .assert_stderr(&format!(
                "open {}: {}",
                fixture.vault.display(),
                msg::VAULT_NOT_FOUND
            ))
            .assert_stderr(&msg::init_hint());
    }

    // set reads its value first, then reports the same missing vault.
    fixture
        .fail("fake-value\n", &["set", "api/one"])
        .assert_stderr(msg::VAULT_NOT_FOUND)
        .assert_stderr(&msg::init_hint());

    assert!(
        !fixture.vault.exists(),
        "a failed open must not create the vault"
    );
    assert!(!fixture.vault.parent().expect("vault dir").exists());
}

// Go: TestOpenRejectsUnknownFormatVersion
#[test]
fn open_rejects_unknown_format_version() {
    let fixture = Fixture::new();

    fixture.set_format_version("999");

    fixture
        .fail("", &["list"])
        .assert_stderr("found version 999, want 2")
        .assert_stderr(msg::FORMAT_VERSION);
}

// Go: TestCreateUsesWALAndSchemaV1
#[test]
fn create_uses_wal_and_schema_v1() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    let db = fixture.db();

    let journal_mode: String = db
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("read journal mode");

    assert_eq!(journal_mode, "wal");

    for (name, want) in SCHEMA {
        let sql: String = db
            .query_row(
                "SELECT sql FROM sqlite_master WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .unwrap_or_else(|err| panic!("{name} must exist: {err}"));

        assert_eq!(sql, want, "{name} must match the reference schema");
    }

    // Nothing beyond the reference schema, bar the indexes SQLite makes
    // for the declared constraints.
    let extra: i64 = db
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_autoindex_%'",
            [],
            |row| row.get(0),
        )
        .expect("count schema objects");

    assert_eq!(extra, 4);
}

// Go: TestOpenRejectsForeignDatabase
//
// A SQLite file without vault_meta is not a vault.
#[test]
fn open_rejects_foreign_database() {
    let fixture = Fixture::empty();

    mkdir(fixture.vault.parent().expect("vault dir"), 0o700);

    Connection::open(&fixture.vault)
        .expect("create a foreign database")
        .execute("CREATE TABLE unrelated (id INTEGER PRIMARY KEY)", [])
        .expect("create an unrelated table");

    fixture
        .fail("", &["list"])
        .assert_stderr(msg::VAULT_CORRUPT);
}

// Go: TestOpenRejectsGarbageFile
//
// A file that is not SQLite at all is an operational error, never
// mislabeled as a half-created vault to move aside.
#[test]
fn open_rejects_garbage_file() {
    let fixture = Fixture::empty();

    mkdir(fixture.vault.parent().expect("vault dir"), 0o700);
    write_file(&fixture.vault, "this is not a sqlite database", 0o600);

    let refused = fixture.fail("", &["list"]);

    assert!(
        refused.stderr.contains("not a database"),
        "{}",
        refused.stderr
    );
    assert!(!refused.stderr.contains(msg::VAULT_CORRUPT));
}

// Go: TestOpenReportsCorruptVault
//
// An empty file at the vault path, the shape a crashed init leaves,
// opens as SQLite but has no vault_meta.
#[test]
fn open_reports_corrupt_vault() {
    let fixture = Fixture::empty();

    mkdir(fixture.vault.parent().expect("vault dir"), 0o700);
    write_file(&fixture.vault, "", 0o600);

    fixture.fail("", &["list"]).assert_stderr(&format!(
        "open {}: {}",
        fixture.vault.display(),
        msg::VAULT_CORRUPT
    ));
}

// Go: TestOpenReportsCorruptVaultOnMissingVersionRow
//
// The vault_meta table exists but its format_version row is gone. That
// missing row is corrupt metadata.
#[test]
fn open_reports_corrupt_vault_on_missing_version_row() {
    let fixture = Fixture::new();

    fixture.sql("DELETE FROM vault_meta WHERE key = 'format_version'", []);

    fixture
        .fail("", &["list"])
        .assert_stderr(msg::VAULT_CORRUPT);
}

// Go: TestLoosePermissionsFlagsLooseFile
//
// Each loose vault path is reported with its role, its mode, and the
// mode it should carry.
#[test]
fn loose_permissions_flags_each_loose_path() {
    let fixture = Fixture::new();
    let directory = fixture.vault.parent().expect("vault dir");

    chmod(&fixture.vault, 0o644);
    chmod(directory, 0o755);

    let listed = fixture.ok("", &["list"]);

    assert_eq!(
        listed.stderr,
        format!(
            "WARN group or world can access a vault path, run chmod on it label=\"vault file\" \
             loose_path={} mode=0644 chmod=0600\n\
             WARN group or world can access a vault path, run chmod on it label=\"vault directory\" \
             loose_path={} mode=0755 chmod=0700\n",
            fixture.vault.display(),
            directory.display()
        )
    );
}

// The warning fires for whatever verb runs, including one that never
// opens the vault.
#[test]
fn loose_permissions_warn_on_every_verb() {
    let fixture = Fixture::new();
    let next = fixture.passphrase_file_with("fake-next-passphrase");

    chmod(&fixture.vault, 0o640);

    let changed = fixture.ok("", &["passwd", "--new-passphrase-file", arg(&next)]);

    assert!(
        changed
            .stderr
            .contains("group or world can access a vault path")
    );
    assert!(changed.stderr.contains("mode=0640"));
}

// Go: TestLoosePermissionsCleanVaultIsEmpty
//
// A freshly created vault at 0600 in a 0700 directory reports nothing.
#[test]
fn loose_permissions_clean_vault_is_silent() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    let listed = fixture.ok("", &["list"]);
    assert!(
        listed.stderr.is_empty(),
        "a clean vault warns about nothing: {}",
        listed.stderr
    );
}

// Go: TestSchemaRejectsInvalidState
#[test]
fn schema_rejects_invalid_state() {
    let fixture = Fixture::new();
    let db = fixture.db();

    db.execute(
        "INSERT INTO secret (name, created_at, updated_at)
         VALUES ('testing/fake', '2026-01-01', '2026-01-01')",
        [],
    )
    .expect("insert a secret row");

    let rejected = db.execute(
        "INSERT INTO secret_version (secret_id, version_number, state, created_at)
         VALUES (1, 1, 'bogus', '2026-01-01')",
        [],
    );

    assert!(
        rejected.is_err(),
        "state CHECK constraint must reject unknown states"
    );

    // STRICT tables reject a value of the wrong type too.
    let rejected = db.execute(
        "INSERT INTO secret_version (secret_id, version_number, state, created_at)
         VALUES (1, 'not-a-number', 'enabled', '2026-01-01')",
        [],
    );

    assert!(
        rejected.is_err(),
        "STRICT must reject a non-integer version number"
    );
}

// Go: TestCreateAndOpenSurviveURISpecialCharactersInPath,
// TestSQLiteDSNEscapesURISpecialCharacters
//
// A vault path containing '#', '?', or '%' must name the file itself.
// Unescaped, SQLite would truncate the filename at '#' or start its
// query at '?', and the real database would land somewhere else at the
// process umask while the 0600 file stayed an empty decoy.
#[test]
fn create_and_open_survive_uri_special_characters_in_path() {
    for directory in ["my#box", "why?", "100%", "all#of?these%", "%23"] {
        let fixture = Fixture::empty();
        let vault = fixture.root().join(directory).join("vault.db");

        let invoke = |args: &[&str], stdin: &str| {
            let mut command = sandboxed(fixture.root());

            command
                .arg("--identity")
                .arg(&fixture.identity)
                .arg("--vault")
                .arg(&vault)
                .arg("--passphrase-file")
                .arg(&fixture.passphrase_file)
                .args(args);

            run(command, stdin).assert_ok()
        };

        invoke(&["init"], "");

        // The database must be the file init made, not a sibling
        // created later by SQLite at a truncated path.
        let size = fs::metadata(&vault).expect("stat vault").len();

        assert!(
            size > 0,
            "{directory}: the vault at this exact path must hold the database, not be an empty decoy"
        );
        assert_eq!(
            mode_of(&vault),
            0o600,
            "{directory}: the real database must keep 0600, never fall back to the umask"
        );

        // The reopened vault is the one init created.
        invoke(&["set", "uri/probe"], "fake-uri-value\n");

        let revealed = invoke(&["reveal", "uri/probe"], "");
        assert_eq!(revealed.json()["value"], "fake-uri-value");

        // Nothing may appear at the path SQLite would have used had the
        // '#' or '?' been left unescaped.
        let full = arg(&vault);

        for terminator in ['#', '?'] {
            if let Some((truncated, _)) = full.split_once(terminator) {
                assert!(
                    !std::path::Path::new(truncated).exists(),
                    "{directory}: no stray database may appear at the truncated path {truncated:?}"
                );
            }
        }

        // Only the expected entries exist beside the vault.
        let mut entries: Vec<String> = fs::read_dir(vault.parent().expect("vault dir"))
            .expect("list vault dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        entries.sort();

        assert_eq!(
            entries,
            ["vault.db"],
            "{directory}: the vault directory holds the vault alone"
        );
    }
}

// A relative vault path works from the working directory.
#[test]
fn relative_vault_path() {
    let fixture = Fixture::empty();

    let invoke = |args: &[&str], stdin: &str| {
        let mut command = sandboxed(fixture.root());

        command
            .current_dir(fixture.root())
            .args(["--identity", "config/identity.age", "--vault", "vault.db"])
            .arg("--passphrase-file")
            .arg(&fixture.passphrase_file)
            .args(args);

        run(command, stdin).assert_ok()
    };

    invoke(&["init"], "");
    invoke(&["set", "rel/probe"], "fake-relative-value\n");

    assert!(fixture.root().join("vault.db").exists());
    assert_eq!(
        invoke(&["reveal", "rel/probe"], "").json()["value"],
        "fake-relative-value"
    );

    // The fixture's passphrase is the one the identity was sealed with.
    crate::support::load_identity(&fixture.root().join("config/identity.age"), PASSPHRASE);
}

// Go: TestSQLiteDSNKeepsConnectionSettings
//
// secure_delete and the post-purge WAL truncate together mean purged
// ciphertext is gone from the files, not merely unlinked from a row.
// The value is large enough to spill onto overflow pages, which a purge
// frees whole. Without secure_delete those pages keep their bytes.
#[test]
fn purge_scrubs_envelope_bytes_from_the_vault_files() {
    let fixture = Fixture::new();

    fixture.set("purge/scrub", &"fake-purge-payload-".repeat(1000), &[]);

    let envelope = fixture.newest_enabled("purge/scrub").envelope;
    let needle = &envelope[envelope.len() - 64..];
    let holds = |bytes: &[u8]| bytes.windows(needle.len()).any(|window| window == needle);

    assert!(
        holds(&fs::read(&fixture.vault).expect("read vault")),
        "the envelope is in the vault file before the purge"
    );

    fixture.ok("", &["purge", "purge/scrub", "--yes"]);

    assert!(
        !holds(&fs::read(&fixture.vault).expect("read vault")),
        "purged ciphertext must be zeroed in the database file"
    );

    for suffix in ["-wal", "-shm"] {
        if let Ok(bytes) = fs::read(sibling(&fixture.vault, suffix)) {
            assert!(
                !holds(&bytes),
                "purged ciphertext must not linger in the {suffix} file"
            );
        }
    }
}

// A relative vault path that reads like a URI still names one file.
// The vault must land in that file, private, and nowhere else.
#[test]
fn a_relative_vault_path_shaped_like_a_uri_names_the_file_itself() {
    for name in ["file:v.db", "file:w.db?mode=ro"] {
        let mut fixture = Fixture::empty();

        fixture.vault = name.into();

        let invoke = |stdin: &str, args: &[&str]| {
            let mut command = fixture.command(args);

            command.current_dir(fixture.root());

            run(command, stdin)
        };

        invoke("", &["init"]).assert_ok();
        invoke(VALUE_ONE, &["set", "api/one"]).assert_ok();

        let vault = fixture.root().join(name);

        assert_eq!(mode_of(&vault), 0o600, "{name}");

        let recipients: i64 = Connection::open(&vault)
            .expect("open the vault")
            .query_row(
                "SELECT count(*) FROM vault_meta WHERE key = 'recipient'",
                [],
                |row| row.get(0),
            )
            .expect("the vault holds the schema");

        assert_eq!(recipients, 1, "{name}");

        // Nothing but the vault, its lock-free siblings, the identity
        // directory, and the passphrase file is in the directory.
        let stray: Vec<String> = fs::read_dir(fixture.root())
            .expect("list")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|entry| !entry.starts_with(name) && entry != "config" && entry != "passphrase")
            .collect();

        assert!(stray.is_empty(), "{name}: unexpected files {stray:?}");

        let listed = invoke("", &["list", "--json"]).assert_ok().json_array();

        assert_eq!(listed.len(), 1, "{name}");
    }
}
