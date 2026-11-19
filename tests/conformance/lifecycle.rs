//! End-to-end verb lifecycles. Ports `cmd/e2e_internal_test.go`.

use crate::support::{Fixture, SECRET_NAME, VALUE_ONE, VALUE_THREE, VALUE_TWO, arg, msg, sibling};

const PRINT_TEST_KEY: &str = r#"printf '%s' "$FAKE_TEST_KEY""#;

// Go: TestRotationLifecycle
#[test]
fn rotation_lifecycle() {
    let fixture = Fixture::new();

    // Version 1 with an env name.
    let stored = fixture.set(SECRET_NAME, VALUE_ONE, &["--env-name", "FAKE_TEST_KEY"]);
    assert_eq!(stored.json()["version"], 1);
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_ONE);

    // Rotation appends. The old version stays enabled by design.
    let stored = fixture.set(SECRET_NAME, VALUE_TWO, &[]);
    assert_eq!(stored.json()["version"], 2);
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_TWO);

    let shown = fixture.ok("", &["show", SECRET_NAME]).json();
    let versions = shown["versions"].as_array().expect("show lists versions");
    assert_eq!(versions.len(), 2);

    for version in versions {
        assert_eq!(
            version["state"], "enabled",
            "rotation must not auto-disable"
        );
    }

    // Disabling the newest version falls back to the previous one.
    fixture.ok("", &["disable", SECRET_NAME, "2"]);
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_ONE);

    // --revoke-previous disables everything older in one step.
    let stored = fixture
        .set(SECRET_NAME, VALUE_THREE, &["--revoke-previous"])
        .json();
    assert_eq!(stored["version"], 3);
    assert_eq!(
        stored["revokedPrevious"], 1,
        "only version 1 was still enabled"
    );
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_THREE);
}

// Go: TestGetRedactsValue
#[test]
fn get_redacts_value() {
    let fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &[]);

    let got = fixture.ok("", &["get", SECRET_NAME]);

    assert_eq!(got.json()["value"], "[REDACTED]");
    assert!(
        !got.stdout.contains(VALUE_ONE),
        "get must never print plaintext"
    );
    assert!(!got.stderr.contains(VALUE_ONE));
}

// Go: TestVerboseEmitsDebugRecords
#[test]
fn verbose_emits_debug_records() {
    let fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &[]);

    let verbose = fixture.ok("", &["--verbose", "get", SECRET_NAME]);
    assert!(verbose.stderr.contains("vault opened"));
    assert!(verbose.stderr.contains("identity unlocked"));
    assert!(verbose.stderr.contains("newest enabled version resolved"));

    let quiet = fixture.ok("", &["get", SECRET_NAME]);
    assert!(
        !quiet.stderr.contains("vault opened"),
        "debug records must stay behind --verbose"
    );
}

// Go: TestListAndPrefixFiltering
#[test]
fn list_and_prefix_filtering() {
    let fixture = Fixture::new();

    fixture.set("api/stripe/live", VALUE_ONE, &[]);
    fixture.set("db/postgres", VALUE_ONE, &[]);

    let all = fixture.ok("", &["list", "--json"]).json_array();
    assert_eq!(all.len(), 2);

    let filtered = fixture.ok("", &["list", "api/", "--json"]).json_array();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0]["name"], "api/stripe/live");
}

// Go: TestExecInjectsEnvironment
#[test]
fn exec_injects_environment() {
    let fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &["--env-name", "FAKE_TEST_KEY"]);

    let ran = fixture.ok("", &["exec", "--", "sh", "-c", PRINT_TEST_KEY]);
    assert_eq!(ran.stdout, VALUE_ONE);
}

// Go: TestExecCollisionCountsInjectedVariables
//
// The debug summary counts variables the child sees, never appended
// assignments: two secrets sharing one env name inject one variable.
#[test]
fn exec_collision_counts_injected_variables() {
    let fixture = Fixture::new();

    fixture.set("lab/first", VALUE_ONE, &["--env-name", "FAKE_SHARED"]);
    fixture.set("lab/second", VALUE_TWO, &["--env-name", "FAKE_SHARED"]);

    let ran = fixture.ok(
        "",
        &[
            "--verbose",
            "exec",
            "--",
            "sh",
            "-c",
            r#"printf '%s' "$FAKE_SHARED""#,
        ],
    );

    assert!(ran.stderr.contains("env name collision"));
    assert!(ran.stderr.contains("injected=1 not_injected=0"));
    assert_eq!(ran.stdout, VALUE_TWO, "the later secret wins the collision");
}

// Go: TestExecPropagatesExitCode
#[test]
fn exec_propagates_exit_code() {
    let fixture = Fixture::new();

    let ran = fixture.run("", &["exec", "--", "sh", "-c", "exit 3"]);
    assert_eq!(ran.code(), Some(3));
}

// Go: TestExpiryIsStalenessNotDeletion
#[test]
fn expiry_is_staleness_not_deletion() {
    let fixture = Fixture::new();

    fixture.set("stale/probe", VALUE_ONE, &["--expires", "2020-01-02"]);

    let stale = fixture.ok("", &["stale", "--json"]).json_array();
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["name"], "stale/probe");

    // The expired secret warns on stderr and still resolves. The name
    // deliberately avoids "expired" so only the log message can satisfy
    // the assertion.
    let got = fixture.ok("", &["get", "stale/probe"]);
    assert!(got.stderr.contains("secret expired"));
    assert_eq!(fixture.reveal_value("stale/probe"), VALUE_ONE);
}

// Go: TestRekeyKeepsValuesAndRotatesRecipient
#[test]
fn rekey_keeps_values_and_rotates_recipient() {
    let fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &[]);

    let before = fixture.ok("", &["show", SECRET_NAME]).stdout;

    let rekeyed = fixture.ok("", &["rekey"]).json();
    assert_eq!(rekeyed["rekeyedVersions"], 1);

    let recipient = rekeyed["recipient"]
        .as_str()
        .expect("rekey reports the recipient");
    assert!(recipient.starts_with("age1"));

    // The value still resolves through the new identity, and the old
    // identity survives as a backup.
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_ONE);
    assert!(
        sibling(&fixture.identity, ".bak").exists(),
        "rekey must keep the old identity as .bak"
    );

    let after = fixture.ok("", &["show", SECRET_NAME]).stdout;
    assert_eq!(before, after, "rekey must not change metadata");
}

// Go: TestPasswdRotatesPassphrase
#[test]
fn passwd_rotates_passphrase() {
    let mut fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &[]);

    let new_passphrase_file = fixture.passphrase_file_with("fake-new-passphrase");

    fixture.ok(
        "",
        &["passwd", "--new-passphrase-file", arg(&new_passphrase_file)],
    );

    // The old passphrase must stop working.
    fixture.fail("", &["reveal", SECRET_NAME]);

    // The new passphrase resolves the same value.
    fixture.passphrase_file = new_passphrase_file;
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_ONE);
}

// Go: TestDeletePurgeAndRevive
#[test]
fn delete_purge_and_revive() {
    let fixture = Fixture::new();

    fixture.set(SECRET_NAME, VALUE_ONE, &[]);
    fixture.ok("", &["delete", SECRET_NAME]);

    // Deleted secrets do not resolve and leave list.
    fixture
        .fail("", &["get", SECRET_NAME])
        .assert_stderr("deleted");

    let listed = fixture.ok("", &["list", "--json"]);
    assert_eq!(listed.stdout, "[]\n");

    // show still reports the tombstone.
    let shown = fixture.ok("", &["show", SECRET_NAME]).json();
    assert!(shown["deletedAt"].is_string());

    // purge requires --yes and then destroys envelopes.
    fixture
        .fail("", &["purge", SECRET_NAME])
        .assert_stderr("--yes");

    let purged = fixture.ok("", &["purge", SECRET_NAME, "--yes"]).json();
    assert_eq!(purged["destroyedVersions"], 1);

    // A new set revives the name. Version numbers never reset.
    let revived = fixture.set(SECRET_NAME, VALUE_TWO, &[]).json();
    assert_eq!(revived["version"], 2);
    assert_eq!(fixture.reveal_value(SECRET_NAME), VALUE_TWO);
}

// Go: TestSetRejectsInvalidName
#[test]
fn set_rejects_invalid_name() {
    let fixture = Fixture::new();

    fixture
        .fail(format!("{VALUE_ONE}\n"), &["set", "bad name"])
        .assert_stderr(msg::INVALID_NAME);
}
