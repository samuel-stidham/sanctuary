//! The migrate verb. Ports the migrate cases of
//! `cmd/hardening_internal_test.go`, `cmd/straggler_internal_test.go`,
//! and the CLI-reachable cases of `internal/vault/migrate_test.go`.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::thread;

use nix::sys::stat::Mode;
use nix::unistd::mkfifo;

use crate::support::envelope::{self, Frame};
use crate::support::{
    Fixture, PASSPHRASE, VALUE_ONE, VALUE_THREE, VALUE_TWO, command_name, msg, other_key, sibling,
};

// Go: TestMigrateOnNewerFormatDoesNotSuggestMigrate
//
// A vault in a format newer than this build cannot be upgraded by it,
// so the error must point at upgrading the binary, not circularly at
// running migrate.
#[test]
fn migrate_on_newer_format_does_not_suggest_migrate() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    fixture.set_format_version("9");

    let refused = fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::FORMAT_VERSION)
        .assert_stderr("upgrade safetybox");

    assert!(
        !refused
            .stderr
            .contains(&format!("run `{} migrate`", command_name())),
        "the migrate error must not tell the user to run migrate"
    );
}

// Go: TestMigrateUpgradesOldVault, TestOpenLegacyRoundTrip (internal/envelope)
//
// A format 1 vault with legacy envelopes is refused, migrate re-seals
// every envelope into the current frame, and afterward reads work and
// the metadata tamper check is in force.
#[test]
fn migrate_upgrades_old_vault() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_ONE"]);

    fixture.downgrade_to_v1();

    // The format 1 vault is refused until it is migrated, and the
    // refusal says how to fix it.
    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::FORMAT_VERSION)
        .assert_stderr(&format!("run `{} migrate`", command_name()));

    let migrated = fixture.ok("", &["migrate"]);
    assert_eq!(
        migrated.stdout, "{\n  \"migratedVersions\": 1,\n  \"result\": \"migrated\"\n}\n",
        "one version must migrate"
    );

    // Reads work again and return the original value.
    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);

    // The re-sealed envelope carries the current frame with the env
    // name bound in.
    let frame = fixture.open_frame(&fixture.key(), &fixture.newest_enabled("api/one"));
    assert_eq!(
        frame,
        Frame {
            address: envelope::address("api/one", 1),
            env_name: Some("FAKE_ONE".to_owned()),
            expires_at: None,
            value: VALUE_ONE.as_bytes().to_vec(),
        }
    );

    // The tamper check now guards the migrated vault.
    fixture.tamper_env_name("api/one", "FAKE_EVIL");
    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::METADATA_TAMPERED);
}

// Go: TestMigrateReadsPassphraseFromFifo
//
// migrate accepts a passphrase from a process substitution, not only a
// regular file. It reads the passphrase before it checks the format, so
// reaching the already-current message proves the fifo was read.
#[test]
fn migrate_reads_passphrase_from_fifo() {
    let mut fixture = Fixture::new();

    let fifo = fixture.root().join("pass.fifo");
    mkfifo(&fifo, Mode::from_bits_truncate(0o600)).expect("create fifo");

    let writer_path = fifo.clone();
    let writer = thread::spawn(move || {
        if let Ok(mut writer) = OpenOptions::new().write(true).open(writer_path) {
            let _ = writeln!(writer, "{PASSPHRASE}");
        }
    });

    fixture.passphrase_file = fifo;

    let migrated = fixture.ok("", &["migrate"]);
    assert!(
        migrated.stderr.contains(msg::ALREADY_CURRENT),
        "migrate must read the passphrase from the fifo and reach the format check"
    );

    writer.join().expect("fifo writer");
}

// Go: TestMigrateStripsNewlineEnvName
//
// A vault written before set validated env names can hold one with a
// newline, which the current frame cannot store. migrate strips the
// newline, warns naming the secret, reconciles the column, and
// completes.
#[test]
fn migrate_strips_newline_env_name() {
    let fixture = Fixture::new();

    fixture.set("api/legacy", VALUE_ONE, &["--env-name", "FAKE_LEGACY"]);

    // Downgrade first, then inject the newline, the order a
    // pre-validation vault would have reached this state in.
    fixture.downgrade_to_v1();
    fixture.tamper_env_name("api/legacy", "FAKE\nLEGACY");

    let migrated = fixture.ok("", &["migrate"]);

    assert_eq!(
        migrated.json()["migratedVersions"],
        1,
        "the one version must migrate"
    );
    assert!(
        migrated.stderr.contains("api/legacy"),
        "the sanitized secret must be named"
    );
    assert!(
        migrated.stderr.contains("newline"),
        "the warning must explain what changed"
    );

    // The value reads back, proving migration completed rather than
    // rolling back.
    assert_eq!(fixture.reveal_value("api/legacy"), VALUE_ONE);

    // The stored env name lost its newline, so column and sealed value
    // agree and the read does not refuse.
    let shown = fixture.ok("", &["show", "api/legacy"]).json();
    assert_eq!(
        shown["envName"], "FAKELEGACY",
        "the newline must be stripped from the stored env name"
    );
}

// Go: TestMigratePreservesVersionShapes
//
// A migration must re-seal an expiry-bearing secret, a disabled
// version, and a soft-deleted secret, while skipping a destroyed
// version whose envelope is NULL.
#[test]
fn migrate_preserves_version_shapes() {
    let fixture = Fixture::new();

    // An expiry-bearing secret. The expiry must stay bound.
    fixture.set(
        "api/expiry",
        VALUE_ONE,
        &["--expires", "2030-01-01T00:00:00Z"],
    );

    // A multi-version secret with the older version disabled.
    fixture.set("api/multi", VALUE_ONE, &[]);
    fixture.set("api/multi", VALUE_TWO, &[]);
    fixture.ok("", &["disable", "api/multi", "1"]);

    // A soft-deleted secret keeps its envelope, so it still migrates.
    fixture.set("api/deleted", VALUE_THREE, &[]);
    fixture.ok("", &["delete", "api/deleted"]);

    // A purged secret has a destroyed version with a NULL envelope,
    // which the migration must skip.
    fixture.set("api/purged", VALUE_ONE, &[]);
    fixture.ok("", &["purge", "api/purged", "--yes"]);

    fixture.downgrade_to_v1();

    let migrated = fixture.ok("", &["migrate"]).json();
    assert_eq!(
        migrated["migratedVersions"], 4,
        "every non-destroyed envelope migrates, the destroyed one is skipped"
    );

    // The expiry-bearing secret reads back and keeps its expiry bound.
    assert_eq!(fixture.reveal_value("api/expiry"), VALUE_ONE);

    let shown = fixture.ok("", &["show", "api/expiry"]).json();
    assert_eq!(
        shown["expiresAt"], "2030-01-01T00:00:00Z",
        "the expiry must survive migration"
    );

    let frame = fixture.open_frame(&fixture.key(), &fixture.newest_enabled("api/expiry"));
    assert_eq!(frame.expires_at.as_deref(), Some("2030-01-01T00:00:00Z"));

    // The multi-version secret resolves its newest enabled version.
    assert_eq!(fixture.reveal_value("api/multi"), VALUE_TWO);

    // The purged secret stays destroyed with no recoverable value.
    let shown = fixture.ok("", &["show", "api/purged"]).json();
    let versions = shown["versions"].as_array().expect("show lists versions");

    assert_eq!(versions.len(), 1);
    assert_eq!(
        versions[0]["state"], "destroyed",
        "the purged version stays destroyed after migration"
    );

    // The soft-deleted secret revives and reads through the new frame.
    fixture.set("api/deleted", VALUE_THREE, &[]);
    assert_eq!(fixture.reveal_value("api/deleted"), VALUE_THREE);
}

// Go: TestMigrateRefusesSwappedRecipient
//
// migrate re-seals every envelope, so it must make the same recipient
// check every read verb makes, with the same tamper guidance.
#[test]
fn migrate_refuses_swapped_recipient() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    fixture.downgrade_to_v1();
    fixture.swap_recipient(&other_key().to_public().to_string());

    fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::RECIPIENT_MISMATCH)
        .assert_stderr("tampered");

    // Nothing was re-sealed: the envelope is still a version 1 frame.
    let payload = envelope::open(&fixture.key(), &fixture.newest_enabled("api/one").envelope);
    assert_eq!(
        payload,
        Frame::legacy(&envelope::address("api/one", 1), VALUE_ONE.as_bytes())
    );
}

// Go: TestMigrateAlreadyCurrentFormat (internal/vault),
// TestMigrateOnAHealthyVaultStillReportsNothingToDo
//
// The repair pass decrypts every envelope to look for stragglers, and
// when it finds none the vault must be left exactly as it was.
#[test]
fn migrate_on_a_healthy_vault_reports_nothing_to_do() {
    let fixture = Fixture::new();

    fixture.set("api/one", "fake-value-one", &[]);
    fixture.set("api/two", "fake-value-two", &[]);

    let before = fs::read(&fixture.vault).expect("read vault");

    let migrated = fixture.ok("", &["migrate"]);

    assert!(migrated.stderr.contains(msg::ALREADY_CURRENT));
    assert!(migrated.stdout.is_empty(), "a no-op migrate emits no JSON");

    assert_eq!(
        before,
        fs::read(&fixture.vault).expect("read vault"),
        "a healthy vault must not be rewritten by the repair scan"
    );

    assert_eq!(fixture.reveal_value("api/one"), "fake-value-one");
}

// Go: TestStrandedLegacyEnvelopeReadHintsAtMigrate
//
// A stranded version 1 row must not fail with a bare tamper-shaped
// error. It names the likely cause and the command that repairs it.
#[test]
fn stranded_legacy_envelope_read_hints_at_migrate() {
    let fixture = Fixture::new();

    fixture.set("api/stranded", "fake-stranded-value", &[]);

    fixture.strand_legacy_envelope("api/stranded");

    let refused = fixture
        .fail("", &["get", "api/stranded"])
        .assert_stderr(msg::LEGACY_ENVELOPE)
        .assert_stderr(&format!("run `{} migrate`", command_name()))
        .assert_stderr("older safetybox");

    assert!(!refused.stderr.contains("fake-stranded-value"));
}

// Go: TestMigrateRepairsAStrandedLegacyEnvelope
#[test]
fn migrate_repairs_a_stranded_legacy_envelope() {
    let fixture = Fixture::new();

    fixture.set("api/stranded", "fake-stranded-value", &[]);
    fixture.set("api/healthy", "fake-healthy-value", &[]);

    fixture.strand_legacy_envelope("api/stranded");

    // The row is unreadable before the repair.
    fixture.fail("", &["get", "api/stranded"]);

    let migrated = fixture.ok("", &["migrate"]);

    assert!(migrated.stderr.contains("repaired"));
    assert_eq!(
        migrated.stdout,
        "{\n  \"migratedVersions\": 1,\n  \"result\": \"repaired\"\n}\n"
    );

    // The original value is readable again, and never had to be retyped.
    assert_eq!(fixture.reveal_value("api/stranded"), "fake-stranded-value");

    // The healthy secret is untouched.
    assert_eq!(fixture.reveal_value("api/healthy"), "fake-healthy-value");
}

/// The advice a decrypt failure carries.
const IDENTITY_ADVICE: &str = "the identity may not match this vault";

// Go: TestMigrateHintsOnceOnACorruptLegacyEnvelope
//
// The same advice on the format upgrade path. Two layers ask for the
// hint there, and a corrupt envelope used to print it twice.
#[test]
fn migrate_hints_once_on_a_corrupt_legacy_envelope() {
    let fixture = Fixture::new();

    fixture.set("api/corrupt", "fake-value", &[]);
    fixture.downgrade_to_v1();

    let row = fixture.newest_enabled("api/corrupt");
    fixture.store_envelope(row.id, b"not-an-envelope-at-all");

    let refused = fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::ENVELOPE_DECRYPT_FAILED);

    assert_eq!(
        refused.stderr.matches(IDENTITY_ADVICE).count(),
        1,
        "the advice must print once, not once per layer: {}",
        refused.stderr
    );
}

// Go: TestMigrateDoesNotRepairARealTamper
//
// Only a genuine version 1 frame is re-sealed. A corrupt or forged
// envelope must keep failing loudly rather than be quietly rewritten.
#[test]
fn migrate_does_not_repair_a_real_tamper() {
    let fixture = Fixture::new();

    fixture.set("api/corrupt", "fake-value", &[]);

    let row = fixture.newest_enabled("api/corrupt");
    fixture.store_envelope(row.id, b"not-an-envelope-at-all");

    let refused = fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::ENVELOPE_DECRYPT_FAILED);

    assert_eq!(
        refused.stderr.matches(IDENTITY_ADVICE).count(),
        1,
        "the advice must print once, not once per layer: {}",
        refused.stderr
    );

    assert_eq!(
        fixture.newest_enabled("api/corrupt").envelope,
        b"not-an-envelope-at-all",
        "corruption must not be silently rewritten"
    );
}

// Go: TestOpenLegacyWrongAddressFails (internal/envelope)
//
// The legacy reader still checks the embedded address, so a version 1
// envelope moved to another row fails the migration whole.
#[test]
fn migrate_refuses_a_legacy_envelope_bound_to_another_address() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);
    fixture.downgrade_to_v1();

    let key = fixture.key();
    let row = fixture.newest_enabled("api/one");
    let moved = envelope::seal(
        &key.to_public(),
        &Frame::legacy(&envelope::address("api/other", 1), VALUE_ONE.as_bytes()),
    );

    fixture.store_envelope(row.id, &moved);

    fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::ADDRESS_MISMATCH);

    // The failed migration rolled back, so the vault is still format 1.
    fixture
        .fail("", &["list"])
        .assert_stderr(msg::FORMAT_VERSION);
}

// Go: TestSealRejectsNewlineInBound, TestSealQuotesABoundFieldCarryingANewline
// (internal/envelope)
//
// A vault-write attacker controls the expiry column that migrate seals
// from. A newline there is refused as an invalid frame, and the refusal
// stays on one line, so injected text cannot pose as its own log line.
#[test]
fn migrate_refuses_a_newline_in_the_bound_expiry_on_one_line() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);
    fixture.downgrade_to_v1();
    fixture.tamper_expires_at("api/one", "2099-01-01\nWARN fake injected line");

    let refused = fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::INVALID_FRAME);

    assert_eq!(
        refused.stderr.lines().count(),
        1,
        "an attacker-controlled newline must not start a new output line: {:?}",
        refused.stderr
    );
}

// Go: TestMigrateMissingVault (internal/vault),
// TestAcquireMigrateLockMissingDirHintsInit,
// TestMigrateLeavesNoStrayLockFileWhenVaultIsMissing
//
// migrate against a missing vault must refuse before taking its lock,
// in a missing directory and in an existing one alike.
#[test]
fn migrate_leaves_no_stray_lock_file_when_vault_is_missing() {
    let fixture = Fixture::new();

    // An existing directory with no vault in it, which is the shape
    // that produced the stray file.
    let directory = fixture.root().join("empty");
    fs::create_dir(&directory).expect("create empty dir");

    let missing_vault = directory.join("vault.db");

    let refused = fixture
        .fail(
            "",
            &["--vault", missing_vault.to_str().expect("utf-8"), "migrate"],
        )
        .assert_stderr(msg::VAULT_NOT_FOUND)
        .assert_stderr(&msg::init_hint());

    assert!(refused.stdout.is_empty());
    assert!(!refused.stderr.contains("panic"));
    assert!(
        !sibling(&missing_vault, ".lock").exists(),
        "a refused migrate must not leave a lock file behind"
    );
    assert_eq!(
        fs::read_dir(&directory).expect("list dir").count(),
        0,
        "the directory must be left exactly as it was"
    );

    // A missing directory surfaces the same hint, not a raw lock error.
    let nowhere = fixture.root().join("nodir").join("vault.db");

    fixture
        .fail(
            "",
            &["--vault", nowhere.to_str().expect("utf-8"), "migrate"],
        )
        .assert_stderr(msg::VAULT_NOT_FOUND)
        .assert_stderr(&msg::init_hint());
}

// Go: TestMigrateRefusesANonRegularVaultPath
//
// A directory at the vault path is not a vault, and reporting that
// before locking keeps the same no-stray-file guarantee.
#[test]
fn migrate_refuses_a_non_regular_vault_path() {
    let fixture = Fixture::new();

    let directory = fixture.root().join("as-dir").join("vault.db");
    fs::create_dir_all(&directory).expect("create dir at the vault path");

    fixture
        .fail(
            "",
            &["--vault", directory.to_str().expect("utf-8"), "migrate"],
        )
        .assert_stderr(msg::VAULT_CORRUPT);

    assert!(
        !sibling(&directory, ".lock").exists(),
        "a refused migrate must not leave a lock file behind"
    );
}
