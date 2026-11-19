//! Shared harness for the conformance suite.
//!
//! Every test drives a safetybox binary as a black box: argv, stdin,
//! stdout, stderr, the exit code, and the files it leaves on disk. That
//! is the only surface the Go original and the Rust port share, so it is
//! the surface the suite pins. Point `SAFETYBOX_BIN` at the Go binary to
//! check the suite against the reference implementation. Without it the
//! suite runs against this crate's own binary.

pub mod envelope;
pub mod pty;

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use age::secrecy::{ExposeSecret, SecretString};
use nix::fcntl::{Flock, FlockArg};
use rusqlite::Connection;
use serde_json::Value;
use tempfile::TempDir;

use self::envelope::Frame;

// Obviously fake test material, never real secrets.
pub const PASSPHRASE: &str = "fake-test-passphrase-not-real";
pub const VALUE_ONE: &str = "fake-value-one-not-real";
pub const VALUE_TWO: &str = "fake-value-two-not-real";
pub const VALUE_THREE: &str = "fake-value-three-not-real";
pub const SECRET_NAME: &str = "api/testing/fake";

/// User-facing error text the binary must reproduce. Go callers branch
/// on sentinel errors with `errors.Is`. A black-box test sees only the
/// message, so each sentinel is pinned by its text.
pub mod msg {
    pub const VAULT_NOT_FOUND: &str = "vault not found";
    pub const VAULT_EXISTS: &str = "vault already exists";
    pub const VAULT_CORRUPT: &str = "vault is not initialized or is corrupt";
    pub const FORMAT_VERSION: &str = "unsupported vault format version";
    pub const STORED_TIME_CORRUPT: &str =
        "stored timestamp is not valid, the vault may have been edited";
    pub const SECRET_NOT_FOUND: &str = "secret not found";
    pub const VERSION_NOT_FOUND: &str = "secret version not found";
    pub const VERSION_DESTROYED: &str = "secret version destroyed";
    pub const SECRET_DELETED: &str = "secret deleted";
    pub const INVALID_NAME: &str = "invalid secret name";
    pub const RECIPIENT_MISMATCH: &str = "vault recipient does not match your identity";
    pub const METADATA_TAMPERED: &str = "vault metadata does not match the sealed value";
    pub const ADDRESS_MISMATCH: &str = "envelope address mismatch";
    pub const ENVELOPE_DECRYPT_FAILED: &str = "envelope decrypt failed";
    pub const LEGACY_ENVELOPE: &str = "envelope is in the superseded version 1 format";
    pub const INVALID_FRAME: &str = "invalid envelope frame";
    pub const IDENTITY_NOT_FOUND: &str = "identity not found";
    pub const IDENTITY_UNSAFE_PERMISSIONS: &str = "identity file permissions too open";
    pub const IDENTITY_UNSAFE_DIR_PERMISSIONS: &str = "identity directory permissions too open";
    pub const IDENTITY_DECRYPT_FAILED: &str = "identity decrypt failed";
    pub const IDENTITY_MALFORMED: &str = "identity file malformed";

    /// The hint that points at init, naming the command the user types.
    pub fn init_hint() -> String {
        format!("run `{} init` first", super::command_name())
    }
    pub const MIGRATE_BUSY: &str = "another safetybox migrate is running";
    pub const IDENTITY_BUSY: &str = "another safetybox rekey or passwd is running";
    pub const ALREADY_CURRENT: &str = "already at the current format";
}

/// The binary under test.
pub fn bin() -> PathBuf {
    std::env::var_os("SAFETYBOX_BIN").map_or_else(
        || PathBuf::from(env!("CARGO_BIN_EXE_sanctuary")),
        PathBuf::from,
    )
}

/// The command name the binary under test goes by, which is what its
/// hints tell the user to type. The Go reference is `safetybox` and the
/// Rust port is `sanctuary`, so both can sit on one PATH. Everything else the
/// two print is held to be the same.
pub fn command_name() -> String {
    bin()
        .file_name()
        .expect("the binary has a file name")
        .to_string_lossy()
        .into_owned()
}

/// Whether the binary under test is the Go reference. Only tests of
/// presentation ask: the version line, and the bytes of help and usage
/// errors, which belong to each binary's own argument parser.
pub fn is_reference() -> bool {
    command_name() == "safetybox"
}

/// A command for the binary under test whose environment cannot reach a
/// real vault. `HOME` points into the test's own directory and every
/// path and color override is dropped, so a run that forgets a flag
/// lands in the sandbox rather than in the developer's own secrets.
pub fn sandboxed(home: &Path) -> Command {
    let mut command = Command::new(bin());

    command.env("HOME", home);

    for name in [
        "SAFETYBOX_VAULT",
        "SAFETYBOX_IDENTITY",
        "XDG_DATA_HOME",
        "XDG_CONFIG_HOME",
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        // A runner sets CI, and both binaries then drop terminal color.
        "CI",
    ] {
        command.env_remove(name);
    }

    command
}

/// What one invocation produced.
#[derive(Debug)]
pub struct Run {
    pub stdout: String,
    pub stderr: String,
    pub status: ExitStatus,
}

impl Run {
    pub fn code(&self) -> Option<i32> {
        self.status.code()
    }

    /// Parses stdout as one JSON document.
    #[track_caller]
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|err| panic!("stdout is not JSON ({err}): {:?}", self.stdout))
    }

    /// Parses stdout as a JSON array.
    #[track_caller]
    pub fn json_array(&self) -> Vec<Value> {
        match self.json() {
            Value::Array(items) => items,
            other => panic!("stdout is not a JSON array: {other}"),
        }
    }

    #[track_caller]
    pub fn assert_ok(self) -> Self {
        assert!(
            self.status.success(),
            "expected success, got {:?}\nstdout: {}\nstderr: {}",
            self.status,
            self.stdout,
            self.stderr
        );

        self
    }

    /// Asserts the generic failure exit. Every safetybox error exits 1.
    /// Only exec propagates another code, and that one is the child's.
    #[track_caller]
    pub fn assert_fails(self) -> Self {
        assert_eq!(
            self.code(),
            Some(1),
            "expected exit 1, got {:?} (signal {:?})\nstdout: {}\nstderr: {}",
            self.status,
            self.status.signal(),
            self.stdout,
            self.stderr
        );

        self
    }

    /// Asserts stderr carries `needle`, the black-box stand-in for
    /// `require.ErrorContains` and `require.ErrorIs`.
    #[track_caller]
    pub fn assert_stderr(self, needle: &str) -> Self {
        assert!(
            self.stderr.contains(needle),
            "stderr must contain {needle:?}\nstderr: {}",
            self.stderr
        );

        self
    }
}

/// How long one invocation may run before the harness gives up on it.
/// Every verb finishes in well under a second, so this only ever fires
/// for a binary that hangs, which must fail a test rather than stall
/// the whole run.
pub const RUN_DEADLINE: Duration = Duration::from_secs(60);

/// Runs `command` with `stdin` piped in and closed, and collects its
/// output.
pub fn run(mut command: Command, stdin: impl AsRef<[u8]>) -> Run {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command.spawn().expect("spawn the binary under test");

    // A verb that fails before reading stdin closes the pipe early, so a
    // write error here is the verb's business, reported through its exit.
    let _ = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(stdin.as_ref());

    collect(child)
}

/// Waits for `child` and gathers whatever it wrote to the pipes it was
/// given. A child that outlives [`RUN_DEADLINE`] is killed and fails
/// the test.
#[track_caller]
pub fn collect(mut child: Child) -> Run {
    fn drain(pipe: Option<impl Read + Send + 'static>) -> Option<JoinHandle<Vec<u8>>> {
        pipe.map(|mut pipe| {
            thread::spawn(move || {
                let mut bytes = Vec::new();
                let _ = pipe.read_to_end(&mut bytes);

                bytes
            })
        })
    }

    let stdout = drain(child.stdout.take());
    let stderr = drain(child.stderr.take());
    let deadline = Instant::now() + RUN_DEADLINE;

    let status = loop {
        if let Some(status) = child.try_wait().expect("poll the binary under test") {
            break status;
        }

        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();

            panic!("the binary under test did not exit within {RUN_DEADLINE:?}");
        }

        thread::sleep(Duration::from_millis(2));
    };

    let text = |reader: Option<JoinHandle<Vec<u8>>>| {
        reader.map_or_else(String::new, |reader| {
            String::from_utf8_lossy(&reader.join().expect("pipe reader")).into_owned()
        })
    };

    Run {
        stdout: text(stdout),
        stderr: text(stderr),
        status,
    }
}

/// Writes `content` to a new file with `mode`.
pub fn write_file(path: &Path, content: impl AsRef<[u8]>, mode: u32) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .unwrap_or_else(|err| panic!("create {}: {err}", path.display()));

    file.write_all(content.as_ref()).expect("write file");

    // The open mode is subject to the umask, so set it exactly.
    chmod(path, mode);
}

pub fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .unwrap_or_else(|err| panic!("chmod {}: {err}", path.display()));
}

/// The permission bits of `path`.
pub fn mode_of(path: &Path) -> u32 {
    fs::metadata(path)
        .unwrap_or_else(|err| panic!("stat {}: {err}", path.display()))
        .permissions()
        .mode()
        & 0o7777
}

pub fn mkdir(path: &Path, mode: u32) {
    DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
        .unwrap_or_else(|err| panic!("mkdir {}: {err}", path.display()));

    chmod(path, mode);
}

/// A path that renders as a `&str` argument.
pub fn arg(path: &Path) -> &str {
    path.to_str().expect("test paths are UTF-8")
}

/// Appends `suffix` to the final component, the way safetybox derives
/// its `.lock`, `.new`, `.bak`, `-wal`, and `-shm` siblings.
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(OsStr::new(suffix));

    PathBuf::from(name)
}

/// Takes the exclusive advisory lock safetybox takes on `lock_path`,
/// standing in for another safetybox process that is mid-operation. The
/// lock is released when the returned guard drops.
pub fn hold_lock(lock_path: &Path) -> Flock<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock_path)
        .unwrap_or_else(|err| panic!("open lock {}: {err}", lock_path.display()));

    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .unwrap_or_else(|(_, errno)| panic!("flock {}: {errno}", lock_path.display()))
}

/// The pristine identity and vault a real `init` produced, shared by
/// every fixture. `init` pays the scrypt KDF, so running it once keeps
/// the suite fast. The init tests still run the real verb.
struct Template {
    identity: Vec<u8>,
    vault: Vec<u8>,
}

fn template() -> &'static Template {
    static TEMPLATE: OnceLock<Template> = OnceLock::new();

    TEMPLATE.get_or_init(|| {
        let fixture = Fixture::empty();

        fixture.ok("", &["init"]);

        assert!(
            !sibling(&fixture.vault, "-wal").exists(),
            "a closed vault must leave no write-ahead log to copy"
        );

        Template {
            identity: fs::read(&fixture.identity).expect("read template identity"),
            vault: fs::read(&fixture.vault).expect("read template vault"),
        }
    })
}

/// An identity and vault in a private temp directory.
pub struct Fixture {
    root: TempDir,
    pub identity: PathBuf,
    pub vault: PathBuf,
    pub passphrase_file: PathBuf,
}

impl Fixture {
    /// Paths and a passphrase file, with nothing initialized.
    pub fn empty() -> Self {
        let root = TempDir::new().expect("create temp dir");
        let identity = root.path().join("config").join("identity.age");
        let vault = root.path().join("data").join("vault.db");
        let passphrase_file = root.path().join("passphrase");

        write_file(&passphrase_file, format!("{PASSPHRASE}\n"), 0o600);

        Self {
            root,
            identity,
            vault,
            passphrase_file,
        }
    }

    /// An initialized identity and vault.
    pub fn new() -> Self {
        let fixture = Self::empty();
        let template = template();

        mkdir(fixture.identity.parent().expect("identity dir"), 0o700);
        mkdir(fixture.vault.parent().expect("vault dir"), 0o700);
        write_file(&fixture.identity, &template.identity, 0o600);
        write_file(&fixture.vault, &template.vault, 0o600);

        fixture
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    /// The binary with the fixture's global flags ahead of `args`.
    /// Global flags go before the verb: anything after the exec command
    /// name belongs to the child, never to safetybox.
    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = sandboxed(self.root());

        command
            .arg("--identity")
            .arg(&self.identity)
            .arg("--vault")
            .arg(&self.vault)
            .arg("--passphrase-file")
            .arg(&self.passphrase_file)
            .args(args);

        command
    }

    pub fn run(&self, stdin: impl AsRef<[u8]>, args: &[&str]) -> Run {
        run(self.command(args), stdin)
    }

    #[track_caller]
    pub fn ok(&self, stdin: impl AsRef<[u8]>, args: &[&str]) -> Run {
        self.run(stdin, args).assert_ok()
    }

    #[track_caller]
    pub fn fail(&self, stdin: impl AsRef<[u8]>, args: &[&str]) -> Run {
        self.run(stdin, args).assert_fails()
    }

    /// Stores `value` under `name` the way `echo value | safetybox set`
    /// does, trailing newline included.
    #[track_caller]
    pub fn set(&self, name: &str, value: &str, flags: &[&str]) -> Run {
        let mut args = vec!["set", name];
        args.extend_from_slice(flags);

        self.ok(format!("{value}\n"), &args)
    }

    #[track_caller]
    pub fn reveal_value(&self, name: &str) -> String {
        self.ok("", &["reveal", name]).json()["value"]
            .as_str()
            .expect("reveal output carries a value")
            .to_owned()
    }

    /// Writes another 0600 passphrase file holding `passphrase` and
    /// returns its path. The fixture keeps using its own until a test
    /// assigns `passphrase_file`.
    pub fn passphrase_file_with(&self, passphrase: &str) -> PathBuf {
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);

        let path = self.root().join(format!(
            "passphrase-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));

        write_file(&path, format!("{passphrase}\n"), 0o600);

        path
    }

    /// A direct handle on the vault database, standing in for anything
    /// that writes the file without going through safetybox.
    pub fn db(&self) -> Connection {
        Connection::open(&self.vault).expect("open vault database")
    }

    /// Runs one statement against the vault database directly.
    #[track_caller]
    pub fn sql(&self, statement: &str, params: impl rusqlite::Params) -> usize {
        self.db()
            .execute(statement, params)
            .expect("execute direct SQL")
    }

    /// The vault's stored recipient.
    pub fn recipient(&self) -> String {
        self.db()
            .query_row(
                "SELECT value FROM vault_meta WHERE key = 'recipient'",
                [],
                |row| row.get(0),
            )
            .expect("read stored recipient")
    }

    /// Decrypts the identity file with the fixture's passphrase, the
    /// way safetybox itself must: age scrypt around an X25519 secret key.
    pub fn key(&self) -> age::x25519::Identity {
        let passphrase = fs::read_to_string(&self.passphrase_file).expect("read passphrase file");

        load_identity(&self.identity, passphrase.trim_end_matches(['\r', '\n']))
    }

    /// Edits the env name column without re-sealing the value, standing
    /// in for a vault-write attacker.
    pub fn tamper_env_name(&self, name: &str, env_name: &str) {
        let changed = self.sql(
            "UPDATE secret SET env_name = ?1 WHERE name = ?2",
            rusqlite::params![env_name, name],
        );

        assert_eq!(changed, 1, "tamper must hit exactly one secret");
    }

    /// Edits the expiry column without re-sealing the value.
    pub fn tamper_expires_at(&self, name: &str, expires_at: &str) {
        let changed = self.sql(
            "UPDATE secret SET expires_at = ?1 WHERE name = ?2",
            rusqlite::params![expires_at, name],
        );

        assert_eq!(changed, 1, "tamper must hit exactly one secret");
    }

    /// Rewrites the stored recipient, standing in for a vault-write
    /// attacker pointing new writes at their own key.
    pub fn swap_recipient(&self, recipient: &str) {
        self.sql(
            "UPDATE vault_meta SET value = ?1 WHERE key = 'recipient'",
            [recipient],
        );
    }

    /// Rewrites the stored format version, standing in for a vault
    /// written by a different safetybox.
    pub fn set_format_version(&self, version: &str) {
        self.sql(
            "UPDATE vault_meta SET value = ?1 WHERE key = 'format_version'",
            [version],
        );
    }

    /// Every version row that still holds an envelope.
    pub fn version_rows(&self) -> Vec<VersionRow> {
        let db = self.db();

        let mut statement = db
            .prepare(
                "SELECT sv.id, s.name, sv.version_number, sv.envelope
                   FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
                  WHERE sv.envelope IS NOT NULL
                  ORDER BY s.name, sv.version_number",
            )
            .expect("prepare version scan");

        statement
            .query_map([], |row| {
                Ok(VersionRow {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    number: row.get(2)?,
                    envelope: row.get(3)?,
                })
            })
            .expect("scan versions")
            .collect::<Result<_, _>>()
            .expect("read version rows")
    }

    /// The newest enabled version of `name`.
    #[track_caller]
    pub fn newest_enabled(&self, name: &str) -> VersionRow {
        self.db()
            .query_row(
                "SELECT sv.id, s.name, sv.version_number, sv.envelope
                   FROM secret_version sv JOIN secret s ON s.id = sv.secret_id
                  WHERE s.name = ?1 AND sv.state = 'enabled'
                  ORDER BY sv.version_number DESC LIMIT 1",
                [name],
                |row| {
                    Ok(VersionRow {
                        id: row.get(0)?,
                        name: row.get(1)?,
                        number: row.get(2)?,
                        envelope: row.get(3)?,
                    })
                },
            )
            .expect("find newest enabled version")
    }

    /// Overwrites one version's envelope bytes.
    pub fn store_envelope(&self, version_id: i64, envelope: &[u8]) {
        let changed = self.sql(
            "UPDATE secret_version SET envelope = ?1 WHERE id = ?2",
            rusqlite::params![envelope, version_id],
        );

        assert_eq!(changed, 1, "store must hit exactly one version");
    }

    /// Decrypts a stored envelope and parses its current-format frame.
    #[track_caller]
    pub fn open_frame(&self, key: &age::x25519::Identity, row: &VersionRow) -> Frame {
        Frame::parse(&envelope::open(key, &row.envelope))
    }

    /// Rewrites the vault to format 1 with legacy address-only
    /// envelopes, standing in for a vault from an older safetybox.
    pub fn downgrade_to_v1(&self) {
        let key = self.key();

        for row in self.version_rows() {
            let frame = self.open_frame(&key, &row);
            let legacy = envelope::seal(
                &key.to_public(),
                &Frame::legacy(&frame.address, &frame.value),
            );

            self.store_envelope(row.id, &legacy);
        }

        self.set_format_version("1");
    }

    /// Rewrites one secret's newest version into the version 1 frame
    /// while the vault stays at the current format. That is what an
    /// older binary leaves behind when it races a migration.
    pub fn strand_legacy_envelope(&self, name: &str) {
        let key = self.key();
        let row = self.newest_enabled(name);
        let frame = self.open_frame(&key, &row);
        let legacy = envelope::seal(
            &key.to_public(),
            &Frame::legacy(&frame.address, &frame.value),
        );

        self.store_envelope(row.id, &legacy);
    }

    /// Rewrites one secret so its env name is `env_name`, sealing the
    /// envelope to match so the row passes the metadata binding. This is
    /// the attacker with vault write access but no passphrase: sealing
    /// needs only the recipient, which the vault stores in the clear.
    pub fn forge_env_name(&self, name: &str, env_name: &str) {
        let key = self.key();
        let row = self.newest_enabled(name);

        let mut frame = self.open_frame(&key, &row);
        frame.env_name = Some(env_name.to_owned());

        self.store_envelope(row.id, &envelope::seal(&key.to_public(), &frame.encode()));
        self.tamper_env_name(name, env_name);
    }
}

/// One `secret_version` row with its envelope.
#[derive(Debug, Clone)]
pub struct VersionRow {
    pub id: i64,
    pub name: String,
    pub number: i64,
    pub envelope: Vec<u8>,
}

/// Decrypts an identity file with `passphrase` and parses the key.
#[track_caller]
pub fn load_identity(path: &Path, passphrase: &str) -> age::x25519::Identity {
    let sealed = fs::read(path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    let scrypt = age::scrypt::Identity::new(SecretString::from(passphrase.to_owned()));

    let decrypted = age::decrypt(&scrypt, &sealed)
        .unwrap_or_else(|err| panic!("identity must decrypt with the passphrase: {err}"));

    let text = String::from_utf8(decrypted).expect("identity file holds text");

    assert!(
        text.starts_with("AGE-SECRET-KEY-"),
        "identity file must hold an age secret key"
    );

    text.trim()
        .parse()
        .expect("identity file must parse as an X25519 identity")
}

/// A fresh keypair, for an attacker or a second identity.
pub fn other_key() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

/// Encrypts `plaintext` to `passphrase` the way an identity file is
/// stored, at a work factor the reference implementation accepts.
pub fn seal_with_passphrase(passphrase: &str, plaintext: &[u8]) -> Vec<u8> {
    let mut recipient = age::scrypt::Recipient::new(SecretString::from(passphrase.to_owned()));
    recipient.set_work_factor(15);

    age::encrypt(&recipient, plaintext).expect("encrypt to a passphrase")
}

/// The secret key text of `key`, for writing a hand-built identity.
pub fn secret_key_text(key: &age::x25519::Identity) -> String {
    key.to_string().expose_secret().to_owned()
}
