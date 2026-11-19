//! The passphrase-encrypted age identity file.
//!
//! The file is age-encrypted with an scrypt passphrase around one
//! X25519 secret key line. On disk it is 0600 inside a 0700 directory,
//! and a loose containing directory is refused the way ssh refuses one.
//!
//! The scrypt cost is pinned, never left to the library. The age crate
//! would otherwise pick a cost from the speed of the machine it runs
//! on, and the Go original always writes 18. A fixed cost keeps a file
//! written here readable there, on any machine.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, ErrorKind, Write};
use std::iter;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use age::secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;

use crate::locked::Locked;
use crate::secret::read_all_wiping;
use crate::sys::{self, PathError, UNSAFE_BITS};

const FILE_MODE: u32 = 0o600;
const DIR_MODE: u32 = 0o700;

/// The scrypt cost every identity file is written with, as log2 of the
/// iteration count. It is the cost the Go original writes.
const WORK_FACTOR: u8 = 18;

/// The highest scrypt cost a read will pay, which is the cap the Go
/// original reads with. A file that asks for more is refused, so a
/// planted identity cannot stall the machine.
const MAX_WORK_FACTOR: u8 = 22;

/// How every age secret key line starts.
const KEY_PREFIX: &str = "AGE-SECRET-KEY-1";

/// Why an identity could not be read or written.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No identity file exists at the path.
    #[error("{}: identity not found", .path.display())]
    NotFound { path: PathBuf },

    /// A write was pointed at an existing identity.
    #[error("{}: identity already exists", .path.display())]
    Exists { path: PathBuf },

    /// The containing directory is accessible by group or world.
    #[error(
        "directory {} has mode {mode:04o}: identity directory permissions too open",
        .directory.display()
    )]
    UnsafeDirPermissions { directory: PathBuf, mode: u32 },

    /// The identity file is readable by group or world.
    #[error("{} has mode {mode:04o}: identity file permissions too open", .path.display())]
    UnsafePermissions { path: PathBuf, mode: u32 },

    /// The file could not be decrypted. The usual cause is a wrong
    /// passphrase.
    #[error("identity decrypt failed: {0}")]
    DecryptFailed(String),

    /// The decrypted file held no age secret key. The parser's own
    /// complaint is dropped, because it can quote the decrypted bytes.
    #[error("parse identity: identity file malformed")]
    Malformed,

    /// The passphrase is not text. The age crate takes a passphrase as
    /// a string, so bytes that are not UTF-8 cannot be used.
    #[error("passphrase is not valid UTF-8")]
    PassphraseNotText,

    #[error("encrypt identity: {0}")]
    Encrypt(String),

    /// The new file could not be moved over the old one.
    #[error(
        "replace identity file: rename {} {}: {}",
        .from.display(),
        .to.display(),
        sys::describe(.source)
    )]
    Rename {
        from: PathBuf,
        to: PathBuf,
        source: io::Error,
    },

    /// The swap happened and could not be synced. The message must say
    /// the new material is in effect, or the caller would retry with
    /// credentials that no longer work.
    #[error("identity replaced and in effect, but not yet durable: {0}")]
    NotDurable(Box<Error>),

    #[error("{context}: {source}")]
    File { context: String, source: PathError },
}

/// A passphrase held in memory that wipes itself when dropped.
pub struct Passphrase(Zeroizing<Vec<u8>>);

impl Passphrase {
    pub fn new(bytes: Zeroizing<Vec<u8>>) -> Self {
        Self(bytes)
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Reports whether two passphrases hold the same bytes.
    pub fn matches(&self, other: &Self) -> bool {
        self.0 == other.0
    }

    /// The passphrase as the string age wants. The copy wipes itself
    /// when dropped.
    fn to_secret(&self) -> Result<SecretString, Error> {
        let text = std::str::from_utf8(&self.0).map_err(|_| Error::PassphraseNotText)?;

        Ok(SecretString::from(text.to_owned()))
    }
}

impl std::fmt::Debug for Passphrase {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(crate::secret::REDACTED)
    }
}

/// Decrypts the identity file at `path` with `passphrase`.
///
/// The decrypted file bytes sit in locked memory while the key is
/// parsed, and are wiped before this returns. The parsed key wipes
/// itself when dropped.
pub fn load(path: &Path, passphrase: &Passphrase) -> Result<age::x25519::Identity, Error> {
    let path = sys::clean(path);
    let shown = path.display();

    // Open once and stat the descriptor, so the permission check and
    // the read see the same file even if the path is swapped.
    let file = File::open(&path).map_err(|err| match err.kind() {
        ErrorKind::NotFound => Error::NotFound { path: path.clone() },
        _ => file_error(&format!("open identity {shown}"), "open", &path, err),
    })?;

    // The directory check runs after the not-found check, so a missing
    // identity points at init and not at the mode of a directory that
    // holds nothing yet.
    check_directory(&sys::parent(&path))?;

    let metadata = file
        .metadata()
        .map_err(|err| file_error(&format!("stat identity {shown}"), "stat", &path, err))?;

    let mode = metadata.permissions().mode() & 0o777;

    if mode & UNSAFE_BITS != 0 {
        return Err(Error::UnsafePermissions { path, mode });
    }

    let sealed = read_all_wiping(&file)
        .map_err(|err| file_error(&format!("read identity {shown}"), "read", &path, err))?;

    decrypt(&sealed, passphrase)
}

fn decrypt(sealed: &[u8], passphrase: &Passphrase) -> Result<age::x25519::Identity, Error> {
    let mut scrypt = age::scrypt::Identity::new(passphrase.to_secret()?);

    scrypt.set_max_work_factor(MAX_WORK_FACTOR);

    let failed = |err: age::DecryptError| Error::DecryptFailed(decrypt_reason(&err));

    let reader = age::Decryptor::new(sealed)
        .and_then(|decryptor| decryptor.decrypt(iter::once(&scrypt as &dyn age::Identity)))
        .map_err(failed)?;

    // The read wipes every buffer it outgrows, so the key material
    // leaves no unwiped copy behind on its way into locked memory.
    let plaintext =
        read_all_wiping(reader).map_err(|err| Error::DecryptFailed(sys::describe(&err)))?;

    let locked = Locked::copy_of(&plaintext);

    drop(plaintext);

    parse_key(locked.bytes())
}

/// Reads the one secret key line, with any surrounding whitespace.
fn parse_key(plaintext: &[u8]) -> Result<age::x25519::Identity, Error> {
    let line = std::str::from_utf8(plaintext)
        .map_err(|_| Error::Malformed)?
        .trim();

    // The Go original reads the key in upper case only, which is how
    // every age implementation writes it.
    if !line.starts_with(KEY_PREFIX) {
        return Err(Error::Malformed);
    }

    line.parse().map_err(|_: &str| Error::Malformed)
}

/// Why age could not open the file. A wrong passphrase reads as it
/// does in the Go original. Anything else is the library's own wording.
fn decrypt_reason(err: &age::DecryptError) -> String {
    match err {
        age::DecryptError::DecryptionFailed | age::DecryptError::KeyDecryptionFailed => {
            "identity did not match any of the recipients: incorrect identity for recipient \
             block: incorrect passphrase"
                .to_owned()
        }
        other => other.to_string(),
    }
}

/// Encrypts `key` with `passphrase` and creates the file at `path`,
/// 0600 inside a 0700 directory. It never overwrites an existing file.
pub fn write(
    path: &Path,
    key: &age::x25519::Identity,
    passphrase: &Passphrase,
) -> Result<(), Error> {
    let sealed = encrypt(key, passphrase)?;
    let path = sys::clean(path);
    let directory = sys::parent(&path);

    DirBuilder::new()
        .recursive(true)
        .mode(DIR_MODE)
        .create(&directory)
        .map_err(|err| file_error("create identity directory", "mkdir", &directory, err))?;

    // Creating leaves the mode of a directory that already existed
    // untouched, so check it rather than trust the create.
    check_directory(&directory)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .open(&path)
        .map_err(|err| match err.kind() {
            ErrorKind::AlreadyExists => Error::Exists { path: path.clone() },
            _ => file_error("create identity file", "open", &path, err),
        })?;

    // A failure after the exclusive create must unlink the partial
    // file. Leaving it would wedge every retry on "already exists" for
    // a file that guards nothing.
    let written = persist(&mut file, &sealed, &path).and_then(|()| {
        drop(file);

        // Sync the directory so the new file's entry is durable. The
        // staged file that rekey writes must exist on disk before the
        // vault re-encrypts, or a power loss could commit the vault to
        // a key whose file never made it to disk.
        sync_directory(&directory)
    });

    if written.is_err() {
        let _ = fs::remove_file(&path);
    }

    written
}

/// Swaps the identity file for one encrypted to a new passphrase or a
/// new key. It writes a sibling temp file first and renames it over the
/// original, so a crash never leaves a corrupt or missing identity.
pub fn replace(
    path: &Path,
    key: &age::x25519::Identity,
    passphrase: &Passphrase,
) -> Result<(), Error> {
    let path = sys::clean(path);
    let temp = sys::sibling(&path, ".tmp");

    // A crash between an earlier write and its rename leaves a stale
    // temp that would wedge this write on "already exists" forever.
    // The temp only ever exists beside a live identity, so removing a
    // leftover is safe.
    match fs::remove_file(&temp) {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(file_error(
                &format!("remove stale identity temp {}", temp.display()),
                "remove",
                &temp,
                err,
            ));
        }
    }

    write(&temp, key, passphrase)?;

    if let Err(source) = fs::rename(&temp, &path) {
        let _ = fs::remove_file(&temp);

        return Err(Error::Rename {
            from: temp,
            to: path,
            source,
        });
    }

    // Sync the directory so the rename itself is durable. Without it a
    // crash can keep the file's data and lose its directory entry,
    // which leaves the only private key missing.
    sync_directory(&sys::parent(&path)).map_err(|err| Error::NotDurable(Box::new(err)))
}

/// Writes the sealed bytes and syncs them, so a crash cannot leave a
/// zero-length or partial identity. For the sole private key that
/// would be data loss.
fn persist(file: &mut File, sealed: &[u8], path: &Path) -> Result<(), Error> {
    file.write_all(sealed)
        .map_err(|err| file_error("write identity file", "write", path, err))?;

    file.sync_all()
        .map_err(|err| file_error("sync identity file", "sync", path, err))
}

/// Flushes a directory's metadata so a create or rename inside it
/// survives a crash.
pub fn sync_directory(directory: &Path) -> Result<(), Error> {
    let shown = directory.display();

    File::open(directory)
        .map_err(|err| {
            file_error(
                &format!("open identity directory {shown}"),
                "open",
                directory,
                err,
            )
        })?
        .sync_all()
        .map_err(|err| {
            file_error(
                &format!("sync identity directory {shown}"),
                "sync",
                directory,
                err,
            )
        })
}

/// Refuses an identity directory that group or world can reach,
/// whether the directory is fresh or was already there.
fn check_directory(directory: &Path) -> Result<(), Error> {
    let metadata = fs::metadata(directory).map_err(|err| match err.kind() {
        ErrorKind::NotFound => Error::NotFound {
            path: directory.to_owned(),
        },
        _ => file_error(
            &format!("stat identity directory {}", directory.display()),
            "stat",
            directory,
            err,
        ),
    })?;

    let mode = metadata.permissions().mode() & 0o777;

    if mode & UNSAFE_BITS != 0 {
        return Err(Error::UnsafeDirPermissions {
            directory: directory.to_owned(),
            mode,
        });
    }

    Ok(())
}

fn encrypt(key: &age::x25519::Identity, passphrase: &Passphrase) -> Result<Vec<u8>, Error> {
    let mut recipient = age::scrypt::Recipient::new(passphrase.to_secret()?);

    recipient.set_work_factor(WORK_FACTOR);

    let line = Zeroizing::new(format!("{}\n", key.to_string().expose_secret()));

    age::encrypt(&recipient, line.as_bytes()).map_err(|err| Error::Encrypt(err.to_string()))
}

fn file_error(context: &str, operation: &'static str, path: &Path, source: io::Error) -> Error {
    Error::File {
        context: context.to_owned(),
        source: PathError::new(operation, path, source),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use age::secrecy::{ExposeSecret, SecretString};
    use zeroize::Zeroizing;

    use super::{Error, Passphrase, load, replace, write};

    fn passphrase(text: &str) -> Passphrase {
        Passphrase::new(Zeroizing::new(text.as_bytes().to_vec()))
    }

    fn mode_of(path: &std::path::Path) -> u32 {
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    #[test]
    fn written_identity_decrypts_to_one_key_line() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");
        let key = age::x25519::Identity::generate();

        write(&path, &key, &passphrase("fake-passphrase")).expect("write");

        assert_eq!(mode_of(&path), 0o600);
        assert_eq!(mode_of(path.parent().expect("parent")), 0o700);

        let sealed = fs::read(&path).expect("read");
        let scrypt = age::scrypt::Identity::new(SecretString::from("fake-passphrase".to_owned()));
        let plaintext = age::decrypt(&scrypt, &sealed).expect("decrypt");

        assert_eq!(
            plaintext,
            format!("{}\n", key.to_string().expose_secret()).into_bytes()
        );
    }

    #[test]
    fn the_scrypt_cost_is_pinned() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");

        write(
            &path,
            &age::x25519::Identity::generate(),
            &passphrase("fake-passphrase"),
        )
        .expect("write");

        let sealed = fs::read(&path).expect("read");
        let header = String::from_utf8_lossy(&sealed[..80]).into_owned();
        let stanza = header.lines().nth(1).expect("the scrypt stanza");

        assert!(stanza.starts_with("-> scrypt "), "{stanza}");
        assert!(stanza.ends_with(" 18"), "{stanza}");
    }

    #[test]
    fn write_never_overwrites() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");
        let key = age::x25519::Identity::generate();

        write(&path, &key, &passphrase("fake-passphrase")).expect("first write");

        let before = fs::read(&path).expect("read");
        let refused = write(&path, &key, &passphrase("fake-passphrase")).expect_err("second write");

        assert!(matches!(refused, Error::Exists { .. }));
        assert_eq!(
            refused.to_string(),
            format!("{}: identity already exists", path.display())
        );
        assert_eq!(fs::read(&path).expect("read"), before);
    }

    #[test]
    fn a_loose_directory_is_refused_and_left_empty() {
        let directory = tempfile::tempdir().expect("temp dir");
        let loose = directory.path().join("loose");

        fs::create_dir(&loose).expect("mkdir");
        fs::set_permissions(&loose, fs::Permissions::from_mode(0o755)).expect("chmod");

        let refused = write(
            &loose.join("identity.age"),
            &age::x25519::Identity::generate(),
            &passphrase("fake-passphrase"),
        )
        .expect_err("a loose directory");

        assert_eq!(
            refused.to_string(),
            format!(
                "directory {} has mode 0755: identity directory permissions too open",
                loose.display()
            )
        );
        assert_eq!(fs::read_dir(&loose).expect("list").count(), 0);
    }

    #[test]
    fn a_passphrase_that_is_not_text_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");
        let bytes = Passphrase::new(Zeroizing::new(vec![0xff, 0xfe]));

        let refused =
            write(&path, &age::x25519::Identity::generate(), &bytes).expect_err("not text");

        assert!(matches!(refused, Error::PassphraseNotText));
        assert!(!path.exists());
    }

    /// Seals `content` the way another age implementation would.
    fn seal(passphrase: &str, content: &[u8], work_factor: u8) -> Vec<u8> {
        let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));

        recipient.set_work_factor(work_factor);

        age::encrypt(&recipient, content).expect("seal")
    }

    /// An identity file with `sealed` as its content, in a private
    /// directory.
    fn identity_file(directory: &std::path::Path, sealed: &[u8]) -> std::path::PathBuf {
        let config = directory.join("config");
        let path = config.join("identity.age");

        fs::create_dir(&config).expect("mkdir");
        fs::set_permissions(&config, fs::Permissions::from_mode(0o700)).expect("chmod");
        fs::write(&path, sealed).expect("write");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod");

        path
    }

    #[test]
    fn a_written_identity_loads_back() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");
        let key = age::x25519::Identity::generate();

        write(&path, &key, &passphrase("fake-passphrase")).expect("write");

        let loaded = load(&path, &passphrase("fake-passphrase")).expect("load");

        assert_eq!(loaded.to_public().to_string(), key.to_public().to_string());
    }

    #[test]
    fn a_wrong_passphrase_reads_as_in_the_reference() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");

        write(
            &path,
            &age::x25519::Identity::generate(),
            &passphrase("fake-passphrase"),
        )
        .expect("write");

        let refused = load(&path, &passphrase("fake-wrong"))
            .err()
            .expect("wrong passphrase");

        assert_eq!(
            refused.to_string(),
            "identity decrypt failed: identity did not match any of the recipients: \
             incorrect identity for recipient block: incorrect passphrase"
        );
    }

    #[test]
    fn surrounding_whitespace_is_tolerated() {
        let directory = tempfile::tempdir().expect("temp dir");
        let key = age::x25519::Identity::generate();
        let content = format!("\n {}\r\n\n", key.to_string().expose_secret());
        let path = identity_file(
            directory.path(),
            &seal("fake-passphrase", content.as_bytes(), 10),
        );

        let loaded = load(&path, &passphrase("fake-passphrase")).expect("load");

        assert_eq!(loaded.to_public().to_string(), key.to_public().to_string());
    }

    #[test]
    fn content_that_is_not_a_key_is_malformed_and_never_quoted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let key = age::x25519::Identity::generate();
        let lower = key.to_string().expose_secret().to_lowercase();

        for (index, content) in [
            b"fake-content-that-is-not-an-age-key".as_slice(),
            b"",
            &[0xff, 0xfe],
            lower.as_bytes(),
        ]
        .into_iter()
        .enumerate()
        {
            let home = directory.path().join(index.to_string());

            fs::create_dir(&home).expect("mkdir");

            let path = identity_file(&home, &seal("fake-passphrase", content, 10));
            let refused = load(&path, &passphrase("fake-passphrase"))
                .err()
                .expect("not a key");

            assert_eq!(
                refused.to_string(),
                "parse identity: identity file malformed"
            );
        }
    }

    #[test]
    fn a_cost_above_the_cap_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = identity_file(directory.path(), &seal("fake-passphrase", b"fake", 10));

        // Rewrite the cost in the header. The cap is checked before
        // any key is derived, so the broken header check never runs.
        let sealed = fs::read(&path).expect("read");
        let text = String::from_utf8_lossy(&sealed).into_owned();
        let at = text.find(" 10\n").expect("the cost");
        let mut raised = sealed[..at].to_vec();

        raised.extend_from_slice(b" 23");
        raised.extend_from_slice(&sealed[at + 3..]);
        fs::write(&path, raised).expect("write");

        let refused = load(&path, &passphrase("fake-passphrase"))
            .err()
            .expect("too costly");

        assert!(matches!(refused, Error::DecryptFailed(_)), "{refused}");
    }

    #[test]
    fn loose_modes_and_missing_files_are_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = identity_file(directory.path(), b"not an age file");
        let config = path.parent().expect("parent").to_owned();
        let secret = passphrase("fake-passphrase");

        assert!(matches!(
            load(&path, &secret).err().expect("garbage"),
            Error::DecryptFailed(_)
        ));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod");
        assert_eq!(
            load(&path, &secret).err().expect("loose file").to_string(),
            format!(
                "{} has mode 0640: identity file permissions too open",
                path.display()
            )
        );

        fs::set_permissions(&config, fs::Permissions::from_mode(0o755)).expect("chmod");
        assert!(matches!(
            load(&path, &secret).err().expect("loose directory"),
            Error::UnsafeDirPermissions { .. }
        ));

        // A missing file reports not found before the directory mode.
        fs::remove_file(&path).expect("remove");
        assert_eq!(
            load(&path, &secret).err().expect("missing").to_string(),
            format!("{}: identity not found", path.display())
        );
    }

    #[test]
    fn replace_keeps_the_key_and_changes_the_passphrase() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("config").join("identity.age");
        let stale = directory.path().join("config").join("identity.age.tmp");
        let key = age::x25519::Identity::generate();

        write(&path, &key, &passphrase("fake-old")).expect("write");

        // A temp file left by a crashed run does not wedge the swap.
        fs::write(&stale, "fake-leftover").expect("write");

        replace(&path, &key, &passphrase("fake-new")).expect("replace");

        assert!(!stale.exists());
        assert_eq!(mode_of(&path), 0o600);
        assert!(matches!(
            load(&path, &passphrase("fake-old")).err().expect("old one"),
            Error::DecryptFailed(_)
        ));
        assert_eq!(
            load(&path, &passphrase("fake-new"))
                .expect("load")
                .to_public()
                .to_string(),
            key.to_public().to_string()
        );
    }

    #[test]
    fn a_passphrase_never_formats() {
        assert_eq!(format!("{:?}", passphrase("fake-passphrase")), "[REDACTED]");
    }
}
