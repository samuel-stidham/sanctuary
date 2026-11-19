//! The init verb. Ports `cmd/init_internal_test.go`.

use std::fs;

use crate::support::{
    Fixture, PASSPHRASE, arg, load_identity, mkdir, mode_of, msg, sandboxed, write_file,
};

// Go: TestInitEndToEnd
#[test]
fn init_end_to_end() {
    let fixture = Fixture::empty();

    let initialized = fixture.ok("", &["init"]);

    // The identity file exists with ssh-style permissions.
    assert_eq!(mode_of(&fixture.identity), 0o600);
    assert_eq!(
        mode_of(fixture.identity.parent().expect("identity dir")),
        0o700
    );

    // The vault opens and stores a parseable recipient.
    let recipient = fixture.recipient();
    recipient
        .parse::<age::x25519::Recipient>()
        .expect("the stored recipient must parse as an X25519 recipient");

    // The identity file decrypts with the passphrase, trailing newline
    // trimmed, back to an age secret key, and that key is the one the
    // vault encrypts to.
    let key = load_identity(&fixture.identity, PASSPHRASE);
    assert_eq!(key.to_public().to_string(), recipient);

    // The recipient and the backup warning went to stderr.
    assert!(initialized.stderr.contains(&recipient));
    assert!(initialized.stderr.contains("back up the identity file"));
    assert!(initialized.stderr.contains("unrecoverable"));
    assert!(
        initialized.stderr.contains("WARN"),
        "the backup notice must carry the warn badge"
    );
    assert!(initialized.stdout.is_empty(), "init reports on stderr only");
}

// Go: TestInitRefusesExistingIdentity
#[test]
fn init_refuses_existing_identity() {
    let fixture = Fixture::empty();

    fixture.ok("", &["init"]);

    let other_vault = fixture.root().join("data").join("other.db");

    fixture
        .fail("", &["--vault", arg(&other_vault), "init"])
        .assert_stderr("refusing to overwrite");
}

// Go: TestInitRefusesEmptyPassphraseFile
#[test]
fn init_refuses_empty_passphrase_file() {
    let mut fixture = Fixture::empty();

    fixture.passphrase_file = fixture.root().join("blank");
    write_file(&fixture.passphrase_file, "\n", 0o600);

    fixture.fail("", &["init"]).assert_stderr("empty");
}

// Go: TestInitTrimsCRLFFromPassphraseFile
#[test]
fn init_trims_crlf_from_passphrase_file() {
    let mut fixture = Fixture::empty();

    fixture.passphrase_file = fixture.root().join("crlf");
    write_file(&fixture.passphrase_file, format!("{PASSPHRASE}\r\n"), 0o600);

    fixture.ok("", &["init"]);

    // The identity must decrypt with the passphrase minus the CRLF.
    load_identity(&fixture.identity, PASSPHRASE);
}

// Go: TestInitMissingPassphraseFile
#[test]
fn init_missing_passphrase_file() {
    let mut fixture = Fixture::empty();

    fixture.passphrase_file = fixture.root().join("does-not-exist");

    fixture.fail("", &["init"]).assert_stderr("passphrase file");
}

// Go: TestInitWithoutPassphraseFileNeedsTerminal
//
// With no terminal on stdin the interactive prompt must refuse and
// point at --passphrase-file.
#[test]
fn init_without_passphrase_file_needs_terminal() {
    let fixture = Fixture::empty();

    let mut command = sandboxed(fixture.root());
    command
        .arg("--identity")
        .arg(&fixture.identity)
        .arg("--vault")
        .arg(&fixture.vault)
        .arg("init");

    crate::support::run(command, "")
        .assert_fails()
        .assert_stderr("stdin is not a terminal: use --passphrase-file");

    assert!(
        !fixture.identity.exists(),
        "a refused init must write nothing"
    );
}

// Go: TestInitRemovesIdentityWhenVaultCreateFails
#[test]
fn init_removes_identity_when_vault_create_fails() {
    let fixture = Fixture::empty();

    // Pre-create the vault so the create step refuses.
    mkdir(fixture.vault.parent().expect("vault dir"), 0o700);
    write_file(&fixture.vault, "occupied", 0o600);

    fixture.fail("", &["init"]).assert_stderr(msg::VAULT_EXISTS);

    // The freshly written identity must be cleaned up so init stays
    // retryable.
    assert!(
        !fixture.identity.exists(),
        "identity file must be removed on vault failure"
    );
    assert_eq!(
        fs::read(&fixture.vault).expect("read the occupying file"),
        b"occupied",
        "the file init refused to overwrite must be left alone"
    );
}
