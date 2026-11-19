//! The rekey and passwd verbs and the interrupted-rekey heal. Ports the
//! rekey cases of `cmd/hardening_internal_test.go` and
//! `cmd/review_fixes_internal_test.go`, and the rekey cases of
//! `internal/vault/store_test.go` that are reachable through the CLI.

use std::fs;
use std::thread;

use crate::support::envelope::{self, Frame};
use crate::support::{
    Fixture, PASSPHRASE, VALUE_ONE, VALUE_TWO, arg, load_identity, mode_of, msg, run, sandboxed,
    sibling,
};

// A default path with `..` after a directory that does not exist is one
// path, however it is spelled. rekey must find the identity it loaded
// when it comes to swap the files, or the vault ends up on a key the
// identity path does not hold.
#[test]
fn rekey_swaps_the_identity_under_an_unclean_default_path() {
    let fixture = Fixture::empty();
    let config = fixture.root().join("config");
    let data = fixture.root().join("data");

    fs::create_dir(&config).expect("mkdir");
    fs::create_dir(&data).expect("mkdir");

    let unclean_config = format!("{}/./config//absent/..", fixture.root().display());
    let unclean_data = format!("{}/data/absent/..", fixture.root().display());

    let invoke = |stdin: &str, args: &[&str]| {
        let mut command = sandboxed(fixture.root());

        command
            .env("XDG_CONFIG_HOME", &unclean_config)
            .env("XDG_DATA_HOME", &unclean_data)
            .arg("--passphrase-file")
            .arg(&fixture.passphrase_file)
            .args(args);

        run(command, stdin)
    };

    invoke("", &["init"]).assert_ok();
    invoke(VALUE_ONE, &["set", "api/one"]).assert_ok();

    let rekeyed = invoke("", &["rekey", "--json"]).assert_ok().json();
    let identity = config.join("safetybox").join("identity.age");

    assert_eq!(rekeyed["rekeyedVersions"], 1);
    assert_eq!(
        rekeyed["backupIdentity"],
        sibling(&identity, ".bak").to_string_lossy().as_ref()
    );
    assert!(identity.exists());
    assert!(sibling(&identity, ".bak").exists());
    assert!(!sibling(&identity, ".new").exists());

    let revealed = invoke("", &["reveal", "api/one", "--json"])
        .assert_ok()
        .json();

    assert_eq!(revealed["value"], VALUE_ONE);

    // migrate finds the same vault under the same spelling.
    invoke("", &["migrate"]).assert_ok();
}

// Go: TestRekeyPreservesBoundMetadata
//
// rekey re-seals every version with the bound metadata it opened, so an
// env-named, expiring secret must still read after rotation. Losing the
// bound in the reseal would refuse these reads as tampered.
#[test]
fn rekey_preserves_bound_metadata() {
    let fixture = Fixture::new();

    fixture.set(
        "api/rot",
        VALUE_ONE,
        &[
            "--env-name",
            "FAKE_ROT",
            "--expires",
            "2030-01-01T00:00:00Z",
        ],
    );

    fixture.ok("", &["rekey"]);

    // get verifies the sealed env name and expiry against the columns.
    fixture.ok("", &["get", "api/rot"]);

    // reveal returns the original value through the rotated identity.
    assert_eq!(fixture.reveal_value("api/rot"), VALUE_ONE);

    // exec injects the env-named secret, so the sealed env name survived.
    let ran = fixture.ok(
        "",
        &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_ROT""#],
    );
    assert_eq!(
        ran.stdout, VALUE_ONE,
        "the env name and value must survive rekey"
    );

    // The re-sealed envelope carries the same frame, now under the new key.
    let frame = fixture.open_frame(&fixture.key(), &fixture.newest_enabled("api/rot"));
    assert_eq!(
        frame,
        Frame {
            address: envelope::address("api/rot", 1),
            env_name: Some("FAKE_ROT".to_owned()),
            expires_at: Some("2030-01-01T00:00:00Z".to_owned()),
            value: VALUE_ONE.as_bytes().to_vec(),
        }
    );
}

// Go: TestRekeyReplacesEnvelopesAndRecipient (internal/vault)
//
// Enabled and disabled versions rekey. Destroyed versions do not. The
// stored recipient becomes the new key, and the old key opens nothing.
#[test]
fn rekey_replaces_envelopes_and_recipient() {
    let fixture = Fixture::new();

    fixture.set("re/key", VALUE_ONE, &[]);
    fixture.set("re/key", VALUE_TWO, &[]);
    fixture.ok("", &["disable", "re/key", "1"]);

    fixture.set("destroyed/one", VALUE_ONE, &[]);
    fixture.ok("", &["purge", "destroyed/one", "--yes"]);

    let old_recipient = fixture.recipient();
    let old_envelope = fixture.newest_enabled("re/key").envelope;

    let rekeyed = fixture.ok("", &["rekey"]).json();

    assert_eq!(
        rekeyed["rekeyedVersions"], 2,
        "enabled and disabled versions rekey, destroyed do not"
    );

    let new_recipient = fixture.recipient();

    assert_ne!(new_recipient, old_recipient);
    assert_eq!(rekeyed["recipient"], new_recipient.as_str());
    assert_eq!(
        rekeyed["backupIdentity"],
        arg(&sibling(&fixture.identity, ".bak")),
        "rekey reports where the old identity went"
    );

    // The live identity is the new key, and the backup is the old one.
    assert_eq!(fixture.key().to_public().to_string(), new_recipient);
    assert_eq!(
        load_identity(&sibling(&fixture.identity, ".bak"), PASSPHRASE)
            .to_public()
            .to_string(),
        old_recipient
    );
    assert_eq!(mode_of(&fixture.identity), 0o600);
    assert!(
        !sibling(&fixture.identity, ".new").exists(),
        "the staged key was promoted"
    );

    assert_ne!(fixture.newest_enabled("re/key").envelope, old_envelope);
    assert_eq!(fixture.reveal_value("re/key"), VALUE_TWO);
}

// Go: TestRekeyResealsEachVersionFromItsOwnEnvelope (internal/vault)
#[test]
fn rekey_reseals_each_version_from_its_own_envelope() {
    let fixture = Fixture::new();

    fixture.set("alpha/one", "fake-alpha-value", &[]);
    fixture.set("beta/two", "fake-beta-value", &[]);

    fixture.ok("", &["rekey"]);

    assert_eq!(fixture.reveal_value("alpha/one"), "fake-alpha-value");
    assert_eq!(fixture.reveal_value("beta/two"), "fake-beta-value");
}

// Go: TestRekeyFailureRollsBackEverything (internal/vault),
// TestFailedRekeyRemovesStagedKeyOnPreCommitError
//
// A reseal failure rolls the whole vault back: the recipient and every
// envelope stay as they were, and the staged key is removed so a retry
// starts clean.
#[test]
fn rekey_failure_rolls_back_everything() {
    let fixture = Fixture::new();

    fixture.set("aaa/healthy", VALUE_ONE, &[]);
    fixture.set("zzz/corrupt", VALUE_TWO, &[]);

    // The corrupt row sorts last, so the healthy one is re-sealed
    // inside the transaction before the failure.
    let corrupt = fixture.newest_enabled("zzz/corrupt");
    fixture.store_envelope(corrupt.id, b"not-an-envelope-at-all");

    let recipient = fixture.recipient();
    let healthy_envelope = fixture.newest_enabled("aaa/healthy").envelope;
    let identity_bytes = fs::read(&fixture.identity).expect("read identity");

    fixture
        .fail("", &["rekey"])
        .assert_stderr(msg::ENVELOPE_DECRYPT_FAILED);

    assert_eq!(
        fixture.recipient(),
        recipient,
        "recipient must not change on failed rekey"
    );
    assert_eq!(
        fixture.newest_enabled("aaa/healthy").envelope,
        healthy_envelope,
        "envelopes must not change on failed rekey"
    );
    assert_eq!(
        fs::read(&fixture.identity).expect("read identity"),
        identity_bytes,
        "the identity must not change on failed rekey"
    );
    assert!(
        !sibling(&fixture.identity, ".new").exists(),
        "a pre-commit failure must remove the staged key"
    );
    assert!(!sibling(&fixture.identity, ".bak").exists());

    assert_eq!(fixture.reveal_value("aaa/healthy"), VALUE_ONE);
}

// Go: TestAppendVersionAfterRekeyUsesTheRotatedRecipient (internal/vault)
//
// A write after a rekey must seal to the rotated recipient, never the
// retired one. Sealing uses only the public recipient, so the write
// stays passphrase-free.
#[test]
fn set_after_rekey_seals_to_the_rotated_recipient() {
    let mut fixture = Fixture::new();

    fixture.set("race/first", VALUE_ONE, &[]);
    fixture.ok("", &["rekey"]);

    // A wrong passphrase proves set never unlocks the identity.
    let real_passphrase_file = fixture.passphrase_file.clone();
    fixture.passphrase_file = fixture.passphrase_file_with("fake-wrong-passphrase");
    fixture.set("race/second", VALUE_TWO, &[]);
    fixture.passphrase_file = real_passphrase_file;

    let rotated = fixture.key();
    let frame = fixture.open_frame(&rotated, &fixture.newest_enabled("race/second"));

    assert_eq!(frame.value, VALUE_TWO.as_bytes());
    assert_eq!(fixture.reveal_value("race/second"), VALUE_TWO);
}

// Go: TestConcurrentSetAndRekeyLeaveNoVersionOnARetiredRecipient
// (internal/vault)
//
// Every stored version must either be sealed to the recipient the vault
// currently holds, or have been re-sealed by the rekey that rotated it.
// A version sealed to a retired recipient and missed by the reseal loop
// is unreadable by any live identity.
#[test]
fn concurrent_set_and_rekey_leave_no_version_on_a_retired_recipient() {
    const WRITERS: usize = 12;

    let fixture = Fixture::new();

    // Seed a version so the rekey has something to reseal.
    fixture.set("race/seed", "fake-seed-value", &[]);

    thread::scope(|scope| {
        let rekey = scope.spawn(|| fixture.run("", &["rekey"]));

        let writers: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let fixture = &fixture;

                scope.spawn(move || {
                    fixture.run(
                        format!("fake-writer-value-{writer:02}\n"),
                        &["set", &format!("race/writer{writer:02}")],
                    )
                })
            })
            .collect();

        rekey.join().expect("rekey thread").assert_ok();

        for writer in writers {
            // Every concurrent write must either succeed or serialize
            // cleanly behind the rekey.
            writer.join().expect("writer thread").assert_ok();
        }
    });

    let key = fixture.key();

    assert_eq!(key.to_public().to_string(), fixture.recipient());

    let rows = fixture.version_rows();
    assert_eq!(rows.len(), WRITERS + 1);

    for row in rows {
        // Decrypting with the live key proves the version is not
        // stranded on the retired recipient.
        let frame = fixture.open_frame(&key, &row);
        assert_eq!(frame.address, envelope::address(&row.name, row.number));
    }

    let revealed = fixture.ok("", &["reveal", "--prefix", "race"]).json_array();
    assert_eq!(revealed.len(), WRITERS + 1);
}

// Go: TestReadHealsInterruptedRekey
//
// A crash that left the identity at its .new sibling with no identity
// file is repaired on the next read.
#[test]
fn read_heals_interrupted_rekey() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    // Simulate a crash mid-swap: identity gone, .new present.
    fs::rename(&fixture.identity, sibling(&fixture.identity, ".new")).expect("stage identity");

    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
    assert!(
        fixture.identity.exists(),
        "the staged identity must be promoted into place"
    );
    assert!(!sibling(&fixture.identity, ".new").exists());
}

// Go: TestRekeyRefusesWhenVaultNotOnIdentity
//
// Simulates the crash window where a rekey committed the vault to the
// staged key but died before the identity swap. A re-run must refuse
// and point at the staged key, never delete it.
#[test]
fn rekey_refuses_when_vault_not_on_identity() {
    let fixture = Fixture::new();
    let staged = sibling(&fixture.identity, ".new");

    fixture.set("api/one", VALUE_ONE, &[]);

    // A real rekey moves the old key to .bak and promotes the new one.
    fixture.ok("", &["rekey"]);

    // Reconstruct the crash state: vault on the new key, identity back
    // to the old key, new key stranded at the staged sibling.
    fs::rename(&fixture.identity, &staged).expect("strand the new key");
    fs::rename(sibling(&fixture.identity, ".bak"), &fixture.identity).expect("restore the old key");

    fixture
        .fail("", &["rekey"])
        .assert_stderr("not encrypted to the identity")
        .assert_stderr("is the live key");

    assert!(staged.exists(), "the staged live key must never be deleted");

    // Read verbs in this state must hint at the interrupted rekey.
    fixture
        .fail("", &["reveal", "api/one"])
        .assert_stderr(msg::RECIPIENT_MISMATCH)
        .assert_stderr("interrupted rekey");
}

// The other refusal: the vault is on some other key and no staged
// sibling exists, so there is nothing to point at.
#[test]
fn rekey_refuses_a_vault_on_another_key_without_a_staged_sibling() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);
    fixture.swap_recipient(&crate::support::other_key().to_public().to_string());

    fixture
        .fail("", &["rekey"])
        .assert_stderr("refusing to rekey");

    assert!(
        !sibling(&fixture.identity, ".new").exists(),
        "a refused rekey stages nothing"
    );
}

// Go: TestPasswdHealsInterruptedRekey
#[test]
fn passwd_heals_interrupted_rekey() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    // Simulate a crash mid-swap: identity gone, .new present.
    fs::rename(&fixture.identity, sibling(&fixture.identity, ".new")).expect("stage identity");

    let next = fixture.passphrase_file_with("fake-next-passphrase");

    fixture.ok("", &["passwd", "--new-passphrase-file", arg(&next)]);

    assert!(
        fixture.identity.exists(),
        "passwd must promote the staged identity before loading"
    );
}

// Go: TestReplaceSwapsPassphrase (internal/identity)
//
// passwd changes only the passphrase. The key is the same key, the vault
// is untouched, and the file keeps its private mode.
#[test]
fn passwd_keeps_the_key_and_the_vault() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let recipient = fixture.recipient();
    let vault_bytes = fs::read(&fixture.vault).expect("read vault");
    let next = fixture.passphrase_file_with("fake-next-passphrase");

    let changed = fixture.ok("", &["passwd", "--new-passphrase-file", arg(&next)]);

    assert!(changed.stdout.is_empty(), "passwd reports on stderr only");
    assert!(changed.stderr.contains("passphrase changed"));

    let rekeyed = load_identity(&fixture.identity, "fake-next-passphrase");

    assert_eq!(
        rekeyed.to_public().to_string(),
        recipient,
        "the key must not change"
    );
    assert_eq!(fixture.recipient(), recipient);
    assert_eq!(fs::read(&fixture.vault).expect("read vault"), vault_bytes);
    assert_eq!(mode_of(&fixture.identity), 0o600);
    assert!(!sibling(&fixture.identity, ".tmp").exists());
}

// Go: TestReplaceRemovesStaleTemp (internal/identity)
//
// A crashed earlier replace leaves a stale temp sibling. The next one
// must clear it instead of wedging on "already exists".
#[test]
fn passwd_removes_a_stale_temp_file() {
    let fixture = Fixture::new();
    let temp = sibling(&fixture.identity, ".tmp");

    crate::support::write_file(&temp, "stale", 0o600);

    let next = fixture.passphrase_file_with("fake-next-passphrase");

    fixture.ok("", &["passwd", "--new-passphrase-file", arg(&next)]);

    load_identity(&fixture.identity, "fake-next-passphrase");
    assert!(
        !temp.exists(),
        "the temp file must be gone after a successful replace"
    );
}

// A leftover staged key from a crashed rekey is a stale artifact once
// the vault is proven to be on the loaded identity, so the next rekey
// replaces it instead of wedging on "already exists".
#[test]
fn rekey_replaces_a_stale_staged_key() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);
    crate::support::write_file(&sibling(&fixture.identity, ".new"), "stale", 0o600);

    fixture.ok("", &["rekey"]);

    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
    assert!(!sibling(&fixture.identity, ".new").exists());
}

// passwd reads the new passphrase from its own flag, and an empty one
// is refused before the identity is rewritten.
#[test]
fn passwd_refuses_an_empty_new_passphrase() {
    let fixture = Fixture::new();
    let blank = fixture.root().join("blank");

    crate::support::write_file(&blank, "\n", 0o600);

    let before = fs::read(&fixture.identity).expect("read identity");

    fixture
        .fail("", &["passwd", "--new-passphrase-file", arg(&blank)])
        .assert_stderr("passphrase file is empty");

    assert_eq!(fs::read(&fixture.identity).expect("read identity"), before);
}
