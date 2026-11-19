//! The exec verb: run a command with secrets in its environment.
//!
//! Plaintext goes only into the child's environment, which is the
//! feature itself. The child's exit code is passed on as is.

use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use nix::fcntl::AtFlags;
use nix::unistd::{AccessFlags, faccessat};

use super::cli::Globals;
use super::decrypt::for_each_decrypted;
use super::envname::{is_reserved, is_shell_identifier};
use super::{Error, hint, open_vault};
use crate::quote::quote;
use crate::secret::Value;
use crate::sys;
use crate::vault::{Entry, EntryFilter};
use crate::{debug, warn};

/// The shell convention for a process killed by a signal: 128 plus the
/// signal number.
const SIGNAL_EXIT_BASE: i32 = 128;

pub fn run(globals: &Globals, command: &[OsString]) -> Result<(), Error> {
    let environment = build_environment(globals)?;

    let Some((name, arguments)) = command.split_first() else {
        return Err(Error::Usage("exec needs a command to run".to_owned()));
    };

    let shown = name.to_string_lossy();
    let program = locate(name, env::var_os("PATH").as_deref())
        .map_err(|reason| Error::Message(format!("run {shown}: {reason}")))?;

    // The program is found with this process's PATH, never the child's.
    // The child still sees the name it was called by.
    let status = Command::new(&program)
        .arg0(name)
        .args(arguments)
        .env_clear()
        .envs(environment)
        .status()
        .map_err(|err| {
            Error::Message(format!(
                "run {shown}: fork/exec {}: {}",
                program.display(),
                sys::describe(&err)
            ))
        })?;

    // A child killed by a signal reports 128 plus the signal number,
    // so a supervisor that keys on that reads the death correctly.
    let code = match status.signal() {
        Some(signal) => SIGNAL_EXIT_BASE + signal,
        None => status.code().unwrap_or(1),
    };

    match u8::try_from(code) {
        Ok(0) => Ok(()),
        Ok(code) => Err(Error::ChildExit(code)),
        Err(_) => Err(Error::ChildExit(1)),
    }
}

/// Why a command could not be found.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum LocateError {
    #[error("exec: no command")]
    NoCommand,

    #[error("exec: {}: executable file not found in $PATH", quote(.0))]
    NotFound(String),

    /// The command was found through a PATH entry that is not
    /// absolute. Running it would let the working directory decide
    /// what code runs.
    #[error("exec: {}: cannot run executable found relative to current directory", quote(.0))]
    RelativeToCurrentDirectory(String),
}

/// Finds the program `name` refers to. A name with a slash in it is a
/// path and is used as given. A bare name is looked up in `path`, the
/// way the Go original looks it up.
fn locate(name: &OsStr, path: Option<&OsStr>) -> Result<PathBuf, LocateError> {
    if name.is_empty() {
        return Err(LocateError::NoCommand);
    }

    if name.as_bytes().contains(&b'/') {
        return Ok(PathBuf::from(name));
    }

    let shown = || name.to_string_lossy().into_owned();

    for directory in path.map(env::split_paths).into_iter().flatten() {
        // An empty entry means the working directory.
        let directory = if directory.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            directory
        };

        let candidate = sys::clean(&directory.join(name));

        if !is_executable(&candidate) {
            continue;
        }

        if !candidate.is_absolute() {
            return Err(LocateError::RelativeToCurrentDirectory(shown()));
        }

        return Ok(candidate);
    }

    Err(LocateError::NotFound(shown()))
}

/// Whether `path` is a file this process may execute.
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    !metadata.is_dir()
        && faccessat(
            nix::fcntl::AT_FDCWD,
            path,
            AccessFlags::X_OK,
            AtFlags::AT_EACCESS,
        )
        .is_ok()
}

/// One variable of the child's environment.
type Variable = (OsString, OsString);

/// Decrypts every secret that has an env name into a copy of this
/// process's environment.
fn build_environment(globals: &Globals) -> Result<Vec<Variable>, Error> {
    let (entries, recipient) = env_named_entries(globals)?;
    let mut environment: Vec<Variable> = env::vars_os().collect();

    // With nothing to inject, the identity is never touched and the
    // command runs without a passphrase.
    if entries.is_empty() {
        return Ok(environment);
    }

    // Which secret supplied each variable, in the order injected.
    let mut delivered: Vec<(String, String)> = Vec::with_capacity(entries.len());
    let mut not_injectable = 0_usize;

    // The names of secrets withheld for their value alone. The name is
    // a sound one, so a value this process already holds under it
    // would pass for the secret.
    let mut withheld: Vec<String> = Vec::new();

    // exec always selects a batch, never one secret by name. A secret
    // whose metadata does not match is skipped with a warning, so one
    // bad row cannot deny every variable to the child.
    let skipped = for_each_decrypted(
        globals,
        &recipient,
        entries,
        false,
        |entry, _expired, value| {
            let env_name = entry.env_name.as_deref().unwrap_or_default();

            if let Some(reason) = not_injectable_reason(env_name, &value) {
                warn!(
                    "secret skipped",
                    "name" => entry.name.as_str(),
                    "reason" => reason,
                );

                not_injectable += 1;

                // A reserved name keeps what this process inherited,
                // which is the point of reserving it.
                if is_shell_identifier(env_name) && !is_reserved(env_name) {
                    withheld.push(env_name.to_owned());
                }

                return Ok(());
            }

            if let Some((_, previous)) = delivered.iter().rev().find(|(name, _)| name == env_name) {
                warn!(
                    "env name collision, the later secret overrides the earlier value",
                    "env_name" => env_name,
                    "name" => entry.name.as_str(),
                    "previous" => previous.as_str(),
                );
            }

            delivered.push((env_name.to_owned(), entry.name.clone()));

            // A later variable of the same name replaces an earlier
            // one, so the secret wins over what this process inherited.
            environment.push((
                OsString::from(env_name),
                OsString::from_vec(value.expose().to_vec()),
            ));

            Ok(())
        },
    )?;

    // A withheld secret counts only when this process holds a value
    // under its name. With nothing there, nothing is stale, and no
    // warning is due.
    let inherited = |name: &&str| {
        environment
            .iter()
            .any(|(held, _)| held.as_os_str() == *name)
    };

    let stale = stale_names(
        skipped
            .iter()
            .filter_map(|entry| entry.env_name.as_deref())
            .chain(withheld.iter().map(String::as_str).filter(inherited)),
        &delivered,
    );

    // A variable a skipped secret was meant to supply is removed, not
    // left alone. This process may already hold a value under that
    // name, and the child could not tell that one from the real
    // secret. Absent is a state the child can detect. Stale is not.
    environment.retain(|(name, _)| !stale.iter().any(|stale| name.as_os_str() == *stale));

    for name in &stale {
        warn!(
            "variable cleared from the environment, so the child cannot read a stale value",
            "env_name" => *name,
        );
    }

    let mut injected: Vec<&str> = delivered.iter().map(|(name, _)| name.as_str()).collect();

    injected.sort_unstable();
    injected.dedup();

    // `injected` is what the child sees, so a collision counts once.
    // `not_injected` counts every decrypted secret withheld from the
    // child, whichever reason withheld it.
    debug!(
        "child environment built",
        "injected" => injected.len(),
        "not_injected" => not_injectable + skipped.len(),
    );

    Ok(environment)
}

/// Selects every secret that has an env name, and reads the stored
/// recipient for the decrypt path to verify. The vault is closed
/// before anything is decrypted.
fn env_named_entries(globals: &Globals) -> Result<(Vec<Entry>, String), Error> {
    let vault = open_vault(globals)?;

    let entries = vault
        .entries(EntryFilter {
            prefix: "",
            env_named: true,
        })
        .map_err(hint::vault)?;

    let recipient = vault
        .recipient()
        .map_err(|err| hint::vault_in("read stored recipient", err))?;

    Ok((entries, recipient))
}

/// Why a secret cannot become a variable of the child's environment,
/// or nothing when it can. reveal refuses the same things for its
/// shell output.
fn not_injectable_reason(env_name: &str, value: &Value) -> Option<String> {
    if !is_shell_identifier(env_name) {
        return Some(format!(
            "env name {} is not a valid variable name",
            quote(env_name)
        ));
    }

    // set refuses these names, but a row can be older than that check
    // or forged, since sealing needs only the recipient the vault
    // stores in the clear. Skipping leaves the child the PATH it
    // inherited, not one the vault supplied.
    if is_reserved(env_name) {
        return Some(format!(
            "env name {} is reserved, so a secret must not supply it",
            quote(env_name)
        ));
    }

    if value.expose().contains(&0) {
        return Some(
            "value contains a NUL byte, which an environment variable cannot hold".to_owned(),
        );
    }

    // The kernel refuses to start any program when one variable is
    // over its limit. Left in, this one secret would fail every exec,
    // including commands that never read it.
    if let Some(limit) = variable_limit()
        && env_name.len() + 1 + value.expose().len() + 1 > limit
    {
        return Some(format!(
            "value is too large for an environment variable, which holds at most {} bytes \
             under this name",
            limit.saturating_sub(env_name.len() + 2)
        ));
    }

    None
}

/// The most bytes one `NAME=value` string may take, with its
/// terminator, or nothing where the system sets no such limit. Linux
/// allows 32 pages for each string. Other systems limit only the total.
fn variable_limit() -> Option<usize> {
    const PAGES_PER_STRING: usize = 32;

    if !cfg!(target_os = "linux") {
        return None;
    }

    // SAFETY: sysconf reads a system constant and touches no memory of
    // this program.
    let page = unsafe { nix::libc::sysconf(nix::libc::_SC_PAGESIZE) };

    usize::try_from(page)
        .ok()
        .filter(|page| *page > 0)
        .map(|page| page * PAGES_PER_STRING)
}

/// The variable names a skipped or withheld secret was meant to supply
/// and nothing else did. A name another secret supplied is current, so it stays.
fn stale_names<'a>(
    skipped: impl Iterator<Item = &'a str>,
    delivered: &[(String, String)],
) -> Vec<&'a str> {
    let mut stale: Vec<&str> = Vec::new();

    for env_name in skipped {
        if is_shell_identifier(env_name)
            && !delivered.iter().any(|(name, _)| name == env_name)
            && !stale.contains(&env_name)
        {
            stale.push(env_name);
        }
    }

    stale
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use super::{LocateError, locate, not_injectable_reason, stale_names};
    use crate::secret::Value;
    use crate::vault::Entry;

    fn entry(name: &str, env_name: Option<&str>) -> Entry {
        Entry {
            name: name.to_owned(),
            env_name: env_name.map(str::to_owned),
            version: 1,
            expires_at: None,
            envelope: Vec::new(),
        }
    }

    #[test]
    fn a_name_with_a_slash_is_used_as_given() {
        assert_eq!(
            locate(OsStr::new("./fake-tool"), None),
            Ok(PathBuf::from("./fake-tool"))
        );
        assert_eq!(
            locate(OsStr::new("bin/fake-tool"), Some(OsStr::new("/nowhere"))),
            Ok(PathBuf::from("bin/fake-tool"))
        );
        assert_eq!(locate(OsStr::new(""), None), Err(LocateError::NoCommand));
    }

    #[test]
    fn a_bare_name_is_looked_up_in_the_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let bin = directory.path().join("bin");
        let executable = |name: &str, mode: u32| {
            let path = bin.join(name);

            fs::write(&path, "#!/bin/sh\n").expect("write");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod");
        };

        fs::create_dir(&bin).expect("mkdir");
        fs::create_dir(bin.join("fake-dir")).expect("mkdir");
        executable("fake-tool", 0o755);
        executable("fake-plain", 0o644);

        let path = format!("/nowhere:{}", bin.display());
        let path = Some(OsStr::new(&path));

        assert_eq!(
            locate(OsStr::new("fake-tool"), path),
            Ok(bin.join("fake-tool"))
        );

        for missing in ["fake-plain", "fake-dir", "fake-absent"] {
            assert_eq!(
                locate(OsStr::new(missing), path),
                Err(LocateError::NotFound(missing.to_owned())),
                "{missing}"
            );
        }

        assert_eq!(
            locate(OsStr::new("fake-tool"), None),
            Err(LocateError::NotFound("fake-tool".to_owned()))
        );
        assert_eq!(
            locate(OsStr::new("fake-tool"), Some(OsStr::new(""))),
            Err(LocateError::NotFound("fake-tool".to_owned()))
        );
    }

    #[test]
    fn locate_errors_read_like_the_reference() {
        assert_eq!(LocateError::NoCommand.to_string(), "exec: no command");
        assert_eq!(
            LocateError::NotFound("fake-tool".to_owned()).to_string(),
            "exec: \"fake-tool\": executable file not found in $PATH"
        );
        assert_eq!(
            LocateError::RelativeToCurrentDirectory("fake-tool".to_owned()).to_string(),
            "exec: \"fake-tool\": cannot run executable found relative to current directory"
        );
    }

    #[test]
    fn what_an_environment_cannot_take() {
        let value = Value::new(b"fake-value");

        assert_eq!(not_injectable_reason("FAKE_NAME", &value), None);
        assert_eq!(
            not_injectable_reason("not-valid", &value).as_deref(),
            Some("env name \"not-valid\" is not a valid variable name")
        );
        assert_eq!(
            not_injectable_reason("LD_PRELOAD", &value).as_deref(),
            Some("env name \"LD_PRELOAD\" is reserved, so a secret must not supply it")
        );
        assert_eq!(
            not_injectable_reason("FAKE_NAME", &Value::new(b"fake\0value")).as_deref(),
            Some("value contains a NUL byte, which an environment variable cannot hold")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_value_the_kernel_would_refuse_is_not_injectable() {
        let limit = super::variable_limit().expect("linux has a limit");

        // FAKE_BIG, the equals sign, and the terminator take 10 bytes.
        let largest = limit - 10;

        assert_eq!(
            not_injectable_reason("FAKE_BIG", &Value::new(&vec![b'f'; largest])),
            None
        );
        assert_eq!(
            not_injectable_reason("FAKE_BIG", &Value::new(&vec![b'f'; largest + 1])).as_deref(),
            Some(
                format!(
                    "value is too large for an environment variable, which holds at most \
                     {largest} bytes under this name"
                )
                .as_str()
            )
        );
    }

    #[test]
    fn only_names_nothing_else_supplied_are_stale() {
        let skipped = [
            entry("api/one", Some("FAKE_ONE")),
            entry("api/two", Some("FAKE_SUPPLIED")),
            entry("api/three", Some("not-valid")),
            entry("api/four", Some("")),
            entry("api/five", None),
            entry("api/six", Some("FAKE_ONE")),
        ];
        let delivered = [("FAKE_SUPPLIED".to_owned(), "api/other".to_owned())];

        let names = skipped.iter().filter_map(|entry| entry.env_name.as_deref());

        assert_eq!(stale_names(names, &delivered), ["FAKE_ONE"]);
    }
}
