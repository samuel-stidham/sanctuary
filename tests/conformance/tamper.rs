//! Tamper evidence and hardening. Ports the recipient, metadata, and
//! output cases of `cmd/hardening_internal_test.go`, the leak and
//! permission cases of `cmd/review_fixes_internal_test.go`, and
//! `cmd/storedtime_internal_test.go`.

use std::fs::OpenOptions;
use std::process::Stdio;

use crate::support::{
    Fixture, VALUE_ONE, VALUE_THREE, VALUE_TWO, chmod, collect, is_reference, mkdir, msg,
    other_key, write_file,
};

// Go: TestPrintJSONReturnsWriteError
//
// A failed stdout write must surface as an error, not a silent exit 0
// with truncated output. /dev/full fails every write, standing in for a
// full disk.
#[test]
fn json_output_reports_a_write_error() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let full = OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .expect("open /dev/full");

    let child = fixture
        .command(&["list"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(full))
        .stderr(Stdio::piped())
        .spawn()
        .expect("run list against a full device");

    collect(child).assert_fails().assert_stderr("write output");
}

// Go: TestPrintJSONSucceedsToBuffer
//
// Pretty JSON is the default: two-space indent and a trailing newline.
// --json compacts it to one line.
#[test]
fn json_output_is_pretty_by_default_and_compact_on_request() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let pretty = fixture.ok("", &["delete", "api/one"]);
    assert_eq!(
        pretty.stdout,
        "{\n  \"name\": \"api/one\",\n  \"result\": \"deleted\"\n}\n"
    );

    fixture.set("api/one", VALUE_ONE, &[]);

    let compact = fixture.ok("", &["delete", "api/one", "--json"]);
    assert_eq!(
        compact.stdout,
        "{\"name\":\"api/one\",\"result\":\"deleted\"}\n"
    );
}

// Go: TestLooseVaultPermsWarnOnOpen
//
// A loosened vault file warns on stderr, unlike the identity file which
// refuses.
#[test]
fn loose_vault_perms_warn_on_open() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    chmod(&fixture.vault, 0o644);

    let listed = fixture.ok("", &["list"]);

    assert!(listed.stderr.contains("group or world can access"));
    assert!(listed.stderr.contains("0644"));
    assert!(
        listed.stderr.contains("vault file"),
        "the label attr must name the loose path's role"
    );
}

// Go: TestHalfCreatedVaultHints
//
// A schema-less file at the vault path must fail with a recovery hint,
// not a raw driver error.
#[test]
fn half_created_vault_hints() {
    let fixture = Fixture::empty();

    mkdir(fixture.vault.parent().expect("vault dir"), 0o700);
    write_file(&fixture.vault, "", 0o600);

    fixture
        .fail("", &["list"])
        .assert_stderr(msg::VAULT_CORRUPT)
        .assert_stderr("half-created");
}

// Go: TestReadRefusesSwappedRecipient
//
// After the stored recipient is swapped, every read verb must refuse
// with a clear tamper error, not decrypt or fail vaguely.
#[test]
fn read_refuses_swapped_recipient() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_ONE"]);

    fixture.swap_recipient(&other_key().to_public().to_string());

    for verb in [
        &["get", "api/one"][..],
        &["reveal", "api/one"],
        &["exec", "--", "true"],
    ] {
        let refused = fixture
            .fail("", verb)
            .assert_stderr(msg::RECIPIENT_MISMATCH);

        assert!(!refused.stdout.contains(VALUE_ONE));
    }
}

// Go: TestReadRefusesTamperedEnvName
//
// An attacker who edits the env name column without re-sealing the
// value is caught on the next read. An explicitly named read fails
// loud. A batch verb skips the mismatching secret with a warning and
// runs on.
#[test]
fn read_refuses_tampered_env_name() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_ONE"]);

    fixture.tamper_env_name("api/one", "FAKE_EVIL");

    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::METADATA_TAMPERED);
    fixture
        .fail("", &["reveal", "api/one"])
        .assert_stderr(msg::METADATA_TAMPERED);

    // exec is a batch verb. The tampered secret is skipped with a
    // warning that names it, and the child still runs, rather than one
    // bad secret denying every variable to every command exec runs.
    let ran = fixture.ok("", &["exec", "--", "true"]);

    assert!(ran.stderr.contains("api/one"));
    assert!(ran.stderr.contains("does not match the sealed value"));
}

// Go: TestReadRefusesTamperedExpiry
#[test]
fn read_refuses_tampered_expiry() {
    let fixture = Fixture::new();

    fixture.set("api/exp", VALUE_ONE, &[]);

    fixture.tamper_expires_at("api/exp", "2099-01-01T00:00:00Z");

    fixture
        .fail("", &["get", "api/exp"])
        .assert_stderr(msg::METADATA_TAMPERED);

    // Removing or moving an expiry the sealed value does carry is caught
    // the same way.
    fixture.set("api/sealed-exp", VALUE_ONE, &["--expires", "2099-01-01"]);

    fixture.tamper_expires_at("api/sealed-exp", "2098-01-01T00:00:00Z");
    fixture
        .fail("", &["get", "api/sealed-exp"])
        .assert_stderr("expiry mismatch");

    fixture.sql(
        "UPDATE secret SET expires_at = NULL WHERE name = 'api/sealed-exp'",
        [],
    );
    fixture
        .fail("", &["get", "api/sealed-exp"])
        .assert_stderr("expiry mismatch");
}

// Go: TestReadRefusesEmptyEnvName
//
// The store maps an empty env name to NULL and never writes a present
// empty string, so a valid-but-empty env_name column is a tampered
// state the frame cannot represent. Flipping NULL to empty also pulls
// the secret into the env-named filter, so an explicit read must refuse
// and the batch selection must skip it rather than print its value.
#[test]
fn read_refuses_empty_env_name() {
    let fixture = Fixture::new();

    fixture.set("api/noenv", VALUE_ONE, &[]);

    fixture.tamper_env_name("api/noenv", "");

    fixture
        .fail("", &["get", "api/noenv"])
        .assert_stderr(msg::METADATA_TAMPERED);
    fixture
        .fail("", &["reveal", "api/noenv"])
        .assert_stderr(msg::METADATA_TAMPERED);

    let revealed = fixture.ok("", &["reveal", "--env"]);

    assert!(
        !revealed.stdout.contains(VALUE_ONE),
        "the flipped secret's value must not be printed"
    );
    assert!(
        revealed.stderr.contains("api/noenv"),
        "the skipped secret must be named"
    );
}

// Go: TestDisabledNewestVersionFailsSafeAfterMetadataChange
//
// Changing a secret's env name writes a new version, and disabling that
// version leaves the older enabled version bound to the old metadata
// while the column holds the new value. An explicit read refuses. A
// batch verb skips it and still delivers the healthy secrets.
// Re-setting the secret reconciles the state.
#[test]
fn disabled_newest_version_fails_safe_after_metadata_change() {
    let fixture = Fixture::new();

    fixture.set("api/healthy", VALUE_TWO, &["--env-name", "FAKE_HEALTHY"]);

    // Version 1 has no env name, version 2 adds one, then version 2 is
    // disabled, so the newest enabled version is 1 with stale metadata.
    fixture.set("api/foo", VALUE_ONE, &[]);
    fixture.set("api/foo", VALUE_ONE, &["--env-name", "FAKE_FOO"]);
    fixture.ok("", &["disable", "api/foo", "2"]);

    fixture
        .fail("", &["get", "api/foo"])
        .assert_stderr(msg::METADATA_TAMPERED);
    fixture
        .fail("", &["reveal", "api/foo"])
        .assert_stderr(msg::METADATA_TAMPERED);

    let ran = fixture.ok(
        "",
        &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_HEALTHY""#],
    );

    assert_eq!(
        ran.stdout, VALUE_TWO,
        "the healthy secret must still inject"
    );
    assert!(
        ran.stderr.contains("api/foo"),
        "the skipped stale secret must be named"
    );

    fixture.set("api/foo", VALUE_THREE, &["--env-name", "FAKE_FOO"]);
    assert_eq!(fixture.reveal_value("api/foo"), VALUE_THREE);
}

// Go: TestSetClearsExpiry
//
// An explicit empty --expires removes an existing expiry instead of
// silently keeping it.
#[test]
fn set_clears_expiry() {
    let fixture = Fixture::new();

    fixture.set("exp/clear", VALUE_ONE, &["--expires", "2020-01-01"]);

    let shown = fixture.ok("", &["show", "exp/clear"]).json();
    assert_eq!(
        shown["expiresAt"], "2020-01-01T00:00:00Z",
        "expiry must be set first"
    );

    fixture.set("exp/clear", VALUE_TWO, &["--expires", ""]);

    let shown = fixture.ok("", &["show", "exp/clear"]).json();
    assert!(
        shown.get("expiresAt").is_none(),
        "empty --expires must clear the expiry"
    );
}

// Go: TestSetClearsEnvName
//
// An explicit empty --env-name removes the env name, so exec stops
// injecting the variable.
#[test]
fn set_clears_env_name() {
    let fixture = Fixture::new();
    let print = &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_CLEARABLE""#];

    fixture.set("env/clear", VALUE_ONE, &["--env-name", "FAKE_CLEARABLE"]);

    let shown = fixture.ok("", &["show", "env/clear"]).json();
    assert_eq!(
        shown["envName"], "FAKE_CLEARABLE",
        "env name must be set first"
    );
    assert_eq!(
        fixture.ok("", print).stdout,
        VALUE_ONE,
        "exec must inject the env-named secret"
    );

    fixture.set("env/clear", VALUE_TWO, &["--env-name", ""]);

    let shown = fixture.ok("", &["show", "env/clear"]).json();
    assert!(
        shown.get("envName").is_none(),
        "empty --env-name must clear the env name"
    );
    assert_eq!(
        fixture.ok("", print).stdout,
        "",
        "a cleared env name must not inject"
    );
}

// Go: TestNonRevealVerbsNeverPrintPlaintext
//
// The fake value appears in neither stdout nor stderr of any verb other
// than reveal, including on a wrong-passphrase error path.
#[test]
fn non_reveal_verbs_never_print_plaintext() {
    let mut fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_KEY_ONE"]);
    fixture.set("api/two", VALUE_TWO, &["--expires", "2020-01-02"]);

    let checks: [&[&str]; 9] = [
        &["set", "api/one", "--env-name", "FAKE_KEY_ONE"],
        &["get", "api/one"],
        &["--verbose", "get", "api/one"],
        &["show", "api/one"],
        &["list", "--json"],
        &["stale", "--json"],
        &["migrate"],
        &["--verbose", "exec", "--", "true"],
        &["rekey"],
    ];

    for args in checks {
        let stdin = if args[0] == "set" {
            format!("{VALUE_ONE}\n")
        } else {
            String::new()
        };
        let ran = fixture.run(stdin, args);

        assert!(
            !ran.stdout.contains(VALUE_ONE),
            "{args:?} leaked plaintext on stdout"
        );
        assert!(
            !ran.stderr.contains(VALUE_ONE),
            "{args:?} leaked plaintext on stderr"
        );
    }

    // The wrong-passphrase error path must not surface plaintext either.
    fixture.passphrase_file = fixture.passphrase_file_with("fake-wrong");

    let refused = fixture.fail("", &["get", "api/one"]);

    assert!(!refused.stdout.contains(VALUE_ONE));
    assert!(!refused.stderr.contains(VALUE_ONE));
}

// Go: TestPassphraseFileRefusesLoosePerms
//
// A regular passphrase file with group or world bits is refused,
// mirroring the identity check.
#[test]
fn passphrase_file_refuses_loose_perms() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    chmod(&fixture.passphrase_file, 0o644);

    fixture
        .fail("", &["reveal", "api/one"])
        .assert_stderr("has mode 0644: run chmod 600 on it");
}

// Go: TestSetRejectsInvalidEnvName
#[test]
fn set_rejects_invalid_env_name() {
    let fixture = Fixture::new();

    fixture
        .fail(
            format!("{VALUE_ONE}\n"),
            &["set", "api/one", "--env-name", "BAD-DASH"],
        )
        .assert_stderr("shell identifier");
}

// Go: TestCorruptStoredTimeNamesTheSecretAndColumn
//
// A timestamp column no safetybox writer produces fails the read, and
// the error names the secret, the column, and what happened.
#[test]
fn corrupt_stored_time_names_the_secret_and_column() {
    for stored in ["", "not-a-time", "2099-01-01"] {
        let fixture = Fixture::new();

        fixture.set("api/broken", "fake-value", &["--env-name", "FAKE_BROKEN"]);

        fixture.tamper_expires_at("api/broken", stored);

        fixture
            .fail("", &["get", "api/broken"])
            .assert_stderr("api/broken")
            .assert_stderr("expires_at")
            .assert_stderr(msg::STORED_TIME_CORRUPT)
            .assert_stderr("edited outside safetybox");
    }
}

// Go: TestCorruptStoredTimeFailsBatchVerbsLoudly
//
// exec and a filtered reveal must fail whole rather than skipping the
// one secret, because a bad column is corruption and not the benign
// metadata drift the skip path exists for.
#[test]
fn corrupt_stored_time_fails_batch_verbs_loudly() {
    for verb in [
        &["exec", "--", "true"][..],
        &["reveal", "--env", "--format", "sh"],
        &["list"],
    ] {
        let fixture = Fixture::new();

        fixture.set(
            "api/healthy",
            "fake-healthy",
            &["--env-name", "FAKE_HEALTHY"],
        );
        fixture.set("api/broken", "fake-broken", &["--env-name", "FAKE_BROKEN"]);

        fixture.tamper_expires_at("api/broken", "");

        let refused = fixture
            .fail("", verb)
            .assert_stderr(msg::STORED_TIME_CORRUPT)
            .assert_stderr("api/broken");

        assert!(
            !refused.stdout.contains("fake-healthy"),
            "corruption must deny the batch rather than deliver part of it"
        );
        assert!(!refused.stdout.contains("fake-broken"));
    }
}

// Go: TestValidExpiryStillParses
//
// Guards against the stricter framing rejecting timestamps safetybox
// itself writes.
#[test]
fn valid_expiry_still_parses() {
    let fixture = Fixture::new();

    fixture.set("api/ok", "fake-value", &["--expires", "2099-01-01"]);

    let shown = fixture.ok("", &["show", "api/ok"]);
    assert!(shown.stdout.contains("2099-01-01"));

    // A cleared expiry stores NULL, which is absent rather than corrupt.
    fixture.set("api/ok", "fake-value", &["--expires", ""]);
    fixture.ok("", &["show", "api/ok"]);
}

// One row edited into text that is not UTF-8 must not take the
// metadata verbs down. Every other secret still lists and shows, and
// the odd name is printed with the replacement character.
#[test]
fn a_name_that_is_not_utf8_does_not_break_the_metadata_verbs() {
    let fixture = Fixture::new();

    fixture.set("api/a", VALUE_ONE, &["--env-name", "FAKE_A"]);
    fixture.set("api/b", "fake-b", &[]);

    let edited = fixture.sql(
        "UPDATE secret SET name = CAST(x'6170692fff62' AS TEXT) WHERE name = 'api/b'",
        [],
    );

    assert_eq!(edited, 1);

    let listed = fixture.ok("", &["list", "--json"]).json_array();
    let names: Vec<&str> = listed
        .iter()
        .map(|entry| entry["name"].as_str().expect("a name"))
        .collect();

    assert_eq!(names, ["api/a", "api/\u{fffd}b"]);

    let shown = fixture.ok("", &["show", "api/a", "--json"]).json();

    assert_eq!(shown["envName"], "FAKE_A");
    assert_eq!(fixture.ok("", &["stale", "--json"]).stdout, "[]\n");

    // The intact secret still decrypts by name.
    fixture.ok("", &["get", "api/a"]);

    // An env name edited the same way does not break listing either.
    let edited = fixture.sql(
        "UPDATE secret SET env_name = CAST(x'46414b45ff' AS TEXT) WHERE name = 'api/a'",
        [],
    );

    assert_eq!(edited, 1);

    let listed = fixture.ok("", &["list", "--json"]).json_array();

    assert_eq!(listed[0]["envName"], "FAKE\u{fffd}");
}

// A stored recipient is accepted only in the form it was written in.
// An upper-case copy names the same key, and a write must still refuse
// it, so both programs agree on which vaults take writes.
#[test]
fn set_refuses_a_stored_recipient_that_is_not_canonical() {
    let fixture = Fixture::new();
    let recipient = fixture.recipient();

    for edited in [
        recipient.to_uppercase(),
        format!("{recipient} "),
        "not-a-recipient".to_owned(),
        String::new(),
    ] {
        fixture.swap_recipient(&edited);

        fixture
            .fail("fake-value", &["set", "api/refused"])
            .assert_stderr(
                "seal api/refused: stored recipient does not parse: malformed recipient",
            );
    }

    fixture.swap_recipient(&recipient);

    assert_eq!(fixture.ok("", &["list", "--json"]).stdout, "[]\n");

    fixture.set("api/accepted", VALUE_ONE, &[]);
    assert_eq!(fixture.reveal_value("api/accepted"), VALUE_ONE);
}

// A secret name edited to hold a newline and an escape sequence must
// not reach the terminal as written. rekey names the version it could
// not re-seal, and that name would otherwise forge a log line.
//
// The Go reference prints the name raw, so it is exempt until it does
// not.
#[test]
fn a_tampered_name_cannot_forge_a_log_line() {
    if is_reference() {
        return;
    }

    let fixture = Fixture::new();

    fixture.set("api/a", VALUE_ONE, &[]);

    let edited = fixture.sql(
        "UPDATE secret SET name = 'api/a' || char(10) || 'INFO fake forged line' || char(27) || '[2K'
          WHERE name = 'api/a'",
        [],
    );

    assert_eq!(edited, 1);

    let refused = fixture.fail("", &["rekey"]);

    assert_eq!(refused.stderr.lines().count(), 1, "{}", refused.stderr);
    assert!(!refused.stderr.contains('\u{1b}'), "{:?}", refused.stderr);
    assert!(
        refused
            .stderr
            .starts_with(r#"ERRO reseal "api/a\nINFO fake forged line\x1b[2K" version 1: "#),
        "{}",
        refused.stderr
    );
}
