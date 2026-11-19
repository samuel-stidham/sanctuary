//! Advisory locks. Ports `cmd/lockfile_internal_test.go`,
//! `cmd/lockpath_internal_test.go`, and the lock cases of
//! `cmd/hardening_internal_test.go`.
//!
//! The Go tests call the lock helpers in process. Here the test takes
//! the same `flock` on the same `.lock` sibling a second safetybox would
//! hold, which pins the lock file's location and the lock's kind as
//! well as the refusal.

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};

use crate::support::{Fixture, VALUE_ONE, arg, hold_lock, mode_of, msg, sibling};

// Go: TestMigrateRefusesWhileMigrateLockIsHeld
//
// While one migrate holds the vault lock, a second refuses up front
// with a clear message, instead of blocking on the SQLite write lock.
#[test]
fn migrate_refuses_while_migrate_lock_is_held() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let _held = hold_lock(&sibling(&fixture.vault, ".lock"));

    fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::MIGRATE_BUSY)
        .assert_stderr("retry when it finishes");
}

// Go: TestMigrateRunsAfterMigrateLockIsReleased,
// TestLockOpenStillWorksOnARegularPath
//
// The lock is advisory and transient. The empty lock file is left
// behind on purpose, so a later run locks the existing inode.
#[test]
fn migrate_runs_after_migrate_lock_is_released() {
    let fixture = Fixture::new();
    let lock_path = sibling(&fixture.vault, ".lock");

    fixture.set("api/one", VALUE_ONE, &[]);

    drop(hold_lock(&lock_path));

    let migrated = fixture.ok("", &["migrate"]);
    assert!(migrated.stderr.contains(msg::ALREADY_CURRENT));

    assert!(
        lock_path.exists(),
        "the lock file is a permanent sibling of the vault"
    );
    assert_eq!(
        fs::metadata(&lock_path).expect("stat lock").len(),
        0,
        "the lock file is empty"
    );
    assert_eq!(mode_of(&lock_path), 0o600);

    // A second run must be able to lock the existing file.
    fixture.ok("", &["migrate"]);
}

// Go: TestLockOpenRefusesASymlinkedLockPath
//
// A symlink planted at the lock path would redirect the file the open
// creates. It must be refused, and the symlink's target never created.
#[test]
fn lock_open_refuses_a_symlinked_lock_path() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let target = fixture.root().join("redirected");
    symlink(&target, sibling(&fixture.vault, ".lock")).expect("plant symlink");

    fixture.fail("", &["migrate"]).assert_stderr("open lock");

    assert!(
        !target.exists(),
        "the open must not create the symlink's target"
    );
}

// Go: TestLockPathConvergesForAliasSpellings
//
// A symlink and a path with redundant separators or a parent traversal
// all name the same lock file, so every spelling serializes against
// the canonical one.
#[test]
fn lock_path_converges_for_alias_spellings() {
    let fixture = Fixture::new();
    let directory = fixture.vault.parent().expect("vault dir");

    fixture.set("api/one", VALUE_ONE, &[]);

    let alias = directory.join("alias.db");
    symlink(&fixture.vault, &alias).expect("alias the vault");
    fs::create_dir(directory.join("sub")).expect("create sub dir");

    let _held = hold_lock(&sibling(&fixture.vault, ".lock"));

    let spellings = [
        ("symlink", alias),
        ("redundant separators", directory.join(".").join("vault.db")),
        (
            "parent traversal",
            directory.join("sub").join("..").join("vault.db"),
        ),
    ];

    for (spelling, path) in spellings {
        let refused = fixture.run("", &["--vault", arg(&path), "migrate"]);

        assert_eq!(
            refused.code(),
            Some(1),
            "{spelling} must lock the same file as the canonical path"
        );
        assert!(
            refused.stderr.contains(msg::MIGRATE_BUSY),
            "{spelling} must lock the same file as the canonical path: {}",
            refused.stderr
        );
    }
}

// Go: TestLockPathDivergesForHardlinks, TestBothHardlinkSpellingsCanLockAtOnce
//
// Records the known limit rather than asserting a fix. The lock is
// keyed by path. Two hardlinks to one file are two paths, so each
// derives its own lock file and both runs lock at once. The limit is
// documented in docs/security.md. If hardlinks ever converge, this test
// fails and is the prompt to update the docs.
#[test]
fn lock_path_diverges_for_hardlinks() {
    let fixture = Fixture::new();
    let hardlink = fixture.vault.with_file_name("same-inode.db");

    fixture.set("api/one", VALUE_ONE, &[]);

    fs::hard_link(&fixture.vault, &hardlink).expect("hardlink the vault");

    // Same inode, confirming this really is a hardlink rather than a copy.
    assert_eq!(
        fs::metadata(&fixture.vault).expect("stat vault").ino(),
        fs::metadata(&hardlink).expect("stat hardlink").ino(),
        "the probe must be a real hardlink"
    );

    let _held = hold_lock(&sibling(&fixture.vault, ".lock"));

    // The same spelling is still refused, which is the guarantee that
    // does hold and the one every real invocation relies on.
    fixture
        .fail("", &["migrate"])
        .assert_stderr(msg::MIGRATE_BUSY);

    // Known limit: the hardlinked spelling acquires its own lock.
    let migrated = fixture.ok("", &["--vault", arg(&hardlink), "migrate"]);

    assert!(migrated.stderr.contains(msg::ALREADY_CURRENT));
    assert!(
        sibling(&hardlink, ".lock").exists(),
        "known limit: hard-linked spellings derive separate locks"
    );
}

// Go: TestRekeyRefusesWhileIdentityLockIsHeld
//
// While one identity operation holds the lock, a second rekey refuses
// up front instead of deleting the first one's staged key. passwd
// shares the same lock.
#[test]
fn rekey_and_passwd_refuse_while_identity_lock_is_held() {
    let fixture = Fixture::new();
    let next = fixture.passphrase_file_with("fake-next-passphrase");

    let _held = hold_lock(&sibling(&fixture.identity, ".lock"));

    fixture
        .fail("", &["rekey"])
        .assert_stderr(msg::IDENTITY_BUSY);
    fixture
        .fail("", &["passwd", "--new-passphrase-file", arg(&next)])
        .assert_stderr(msg::IDENTITY_BUSY);

    assert!(
        !sibling(&fixture.identity, ".new").exists(),
        "a refused rekey must stage nothing"
    );
}

// Go: TestRekeyRunsAfterLockIsReleased
#[test]
fn rekey_runs_after_lock_is_released() {
    let fixture = Fixture::new();
    let lock_path = sibling(&fixture.identity, ".lock");

    drop(hold_lock(&lock_path));

    fixture.ok("", &["rekey"]);

    assert!(
        lock_path.exists(),
        "the lock file is a permanent sibling of the identity"
    );
    assert_eq!(mode_of(&lock_path), 0o600);
}

// Go: TestIdentityLockPathResolvesSymlink
//
// A symlink alias of the identity must derive the same lock path as the
// real file, so two spellings serialize instead of taking two locks.
#[test]
fn identity_lock_path_resolves_symlink() {
    let fixture = Fixture::new();
    let alias = fixture.identity.with_file_name("alias.age");

    symlink(&fixture.identity, &alias).expect("alias the identity");

    let _held = hold_lock(&sibling(&fixture.identity, ".lock"));

    fixture
        .fail("", &["--identity", arg(&alias), "rekey"])
        .assert_stderr(msg::IDENTITY_BUSY);
}

// Go: TestAcquireIdentityLockMissingDirHintsInit
//
// The lock is taken before the identity load, so a first-run passwd or
// rekey with no config directory must still surface the init hint, not
// a raw error about a missing lock file.
#[test]
fn identity_lock_in_a_missing_directory_hints_init() {
    let fixture = Fixture::new();
    let missing = fixture.root().join("nodir").join("identity.age");
    let next = fixture.passphrase_file_with("fake-next-passphrase");

    for verb in [
        &["rekey"][..],
        &["passwd", "--new-passphrase-file", arg(&next)],
    ] {
        let mut args = vec!["--identity", arg(&missing)];
        args.extend_from_slice(verb);

        fixture
            .fail("", &args)
            .assert_stderr(msg::IDENTITY_NOT_FOUND)
            .assert_stderr(&msg::init_hint());
    }

    assert!(
        !missing.parent().expect("parent").exists(),
        "a refusal must create nothing"
    );
}
