//! The identity file. Ports `internal/identity/identity_test.go` through
//! the verbs that load and write the identity.

use std::fs;

use crate::support::{
    Fixture, PASSPHRASE, VALUE_ONE, chmod, load_identity, mkdir, mode_of, msg,
    seal_with_passphrase, secret_key_text, sibling, write_file,
};

fn fixture_with_secret() -> Fixture {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    fixture
}

// Go: TestWriteLoadRoundTrip
//
// The identity is an age scrypt file around one X25519 secret key
// line, 0600 inside a 0700 directory, and a read verb loads it back.
#[test]
fn write_load_round_trip() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    assert_eq!(mode_of(&fixture.identity), 0o600);
    assert_eq!(
        mode_of(fixture.identity.parent().expect("identity dir")),
        0o700
    );

    let sealed = fs::read(&fixture.identity).expect("read identity");
    assert!(
        sealed.starts_with(b"age-encryption.org/v1\n-> scrypt "),
        "the identity is a binary age file with one scrypt stanza"
    );

    let key = load_identity(&fixture.identity, PASSPHRASE);
    assert_eq!(key.to_public().to_string(), fixture.recipient());

    fixture.set("api/one", VALUE_ONE, &[]);
    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
}

// An identity file written by another age implementation loads, as
// long as it holds one secret key line. Surrounding whitespace is
// tolerated.
#[test]
fn loads_an_identity_written_by_another_age_implementation() {
    let fixture = fixture_with_secret();
    let key = fixture.key();

    fs::remove_file(&fixture.identity).expect("remove identity");
    write_file(
        &fixture.identity,
        seal_with_passphrase(
            PASSPHRASE,
            format!("\n{}\n\n", secret_key_text(&key)).as_bytes(),
        ),
        0o600,
    );

    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
}

// Go: TestLoadMissingFile
#[test]
fn load_missing_file() {
    let fixture = fixture_with_secret();

    fs::remove_file(&fixture.identity).expect("remove identity");

    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(&format!(
            "{}: {}: {}",
            fixture.identity.display(),
            msg::IDENTITY_NOT_FOUND,
            msg::init_hint()
        ));
}

// Go: TestLoadRefusesOpenPermissions
#[test]
fn load_refuses_open_permissions() {
    let fixture = fixture_with_secret();

    for mode in [0o640, 0o604, 0o644, 0o666] {
        chmod(&fixture.identity, mode);

        let refused = fixture
            .fail("", &["get", "api/one"])
            .assert_stderr(msg::IDENTITY_UNSAFE_PERMISSIONS)
            .assert_stderr(&format!("has mode {mode:04o}"))
            .assert_stderr("run `chmod 600` on the identity file");

        assert!(refused.stdout.is_empty(), "mode {mode:04o} must be refused");
    }
}

// Go: TestLoadRefusesLooseDirectory
#[test]
fn load_refuses_loose_directory() {
    let fixture = fixture_with_secret();

    // Loosen the containing directory after a correct write.
    chmod(fixture.identity.parent().expect("identity dir"), 0o755);

    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::IDENTITY_UNSAFE_DIR_PERMISSIONS)
        .assert_stderr("has mode 0755")
        .assert_stderr("run `chmod 700` on the identity directory");
}

// Go: TestWriteRefusesLooseDirectory
//
// A loose pre-existing directory is refused on write too, and nothing
// is left behind in it.
#[test]
fn write_refuses_loose_directory() {
    let fixture = Fixture::empty();
    let directory = fixture.identity.parent().expect("identity dir");

    mkdir(directory, 0o755);

    fixture
        .fail("", &["init"])
        .assert_stderr(msg::IDENTITY_UNSAFE_DIR_PERMISSIONS);

    assert_eq!(fs::read_dir(directory).expect("list dir").count(), 0);
    assert!(
        !fixture.vault.exists(),
        "a refused init must not create the vault"
    );
}

// Go: TestEmptyPassphraseRejected
//
// An empty passphrase must not produce an identity file.
#[test]
fn empty_passphrase_rejected() {
    let mut fixture = Fixture::empty();

    fixture.passphrase_file = fixture.root().join("blank");
    write_file(&fixture.passphrase_file, "", 0o600);

    fixture
        .fail("", &["init"])
        .assert_stderr("passphrase file is empty");

    assert!(!fixture.identity.exists());
}

// Go: TestLoadWrongPassphrase
#[test]
fn load_wrong_passphrase() {
    let mut fixture = fixture_with_secret();

    fixture.passphrase_file = fixture.passphrase_file_with("fake-wrong-passphrase");

    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::IDENTITY_DECRYPT_FAILED)
        .assert_stderr("check the passphrase");
}

// Go: TestLoadMalformedContent
//
// Valid age encryption wrapping something that is not a key. The error
// must not echo any of the decrypted content.
#[test]
fn load_malformed_content() {
    let fixture = fixture_with_secret();

    fs::remove_file(&fixture.identity).expect("remove identity");
    write_file(
        &fixture.identity,
        seal_with_passphrase(PASSPHRASE, b"fake-content-that-is-not-an-age-key"),
        0o600,
    );

    let refused = fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::IDENTITY_MALFORMED);

    assert!(
        !refused
            .stderr
            .contains("fake-content-that-is-not-an-age-key"),
        "decrypted identity content must never reach an error"
    );
}

// A file that is not an age file at all is a decrypt failure.
#[test]
fn load_garbage_identity_fails_to_decrypt() {
    let fixture = fixture_with_secret();

    fs::remove_file(&fixture.identity).expect("remove identity");
    write_file(&fixture.identity, "this is not an age file", 0o600);

    fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::IDENTITY_DECRYPT_FAILED);
}

// Go: TestWriteRefusesOverwrite
//
// init never overwrites an identity, and leaves it byte for byte.
#[test]
fn write_refuses_overwrite() {
    let fixture = Fixture::new();
    let before = fs::read(&fixture.identity).expect("read identity");

    fixture.fail("", &["init"]).assert_stderr(&format!(
        "identity already exists at {}",
        fixture.identity.display()
    ));

    assert_eq!(fs::read(&fixture.identity).expect("read identity"), before);
}

// Go: TestLoadMissingIdentityReportsNotFoundBeforeDirPerms
//
// A loose but empty directory must report the missing identity, so the
// user is pointed at init rather than at chmod.
#[test]
fn load_missing_identity_reports_not_found_before_dir_perms() {
    let fixture = fixture_with_secret();

    fs::remove_file(&fixture.identity).expect("remove identity");
    chmod(fixture.identity.parent().expect("identity dir"), 0o755);

    let refused = fixture
        .fail("", &["get", "api/one"])
        .assert_stderr(msg::IDENTITY_NOT_FOUND);

    assert!(
        !refused
            .stderr
            .contains(msg::IDENTITY_UNSAFE_DIR_PERMISSIONS)
    );
}

// The identity lock file never trips the directory or file checks.
#[test]
fn lock_sibling_does_not_disturb_loading() {
    let fixture = fixture_with_secret();

    fixture.ok("", &["rekey"]);

    assert!(sibling(&fixture.identity, ".lock").exists());
    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
}
