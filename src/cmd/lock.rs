//! Advisory locks that keep two runs from rewriting one file at once.
//!
//! The lock is an exclusive `flock` on a `.lock` sibling of the file it
//! guards. The kernel drops it when the process exits, so a crash never
//! wedges a later run. The empty lock file is left in place on purpose.
//! Removing it would let a third process lock a fresh inode while a
//! second still holds the old one.

use std::collections::VecDeque;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::libc;

use super::{Error, hint};
use crate::sys::{self, PathError};
use crate::{debug, identity, vault};

/// The lock file is as private as the identity file.
const LOCK_FILE_MODE: u32 = 0o600;

/// The most symbolic links one path may pass through.
const MAX_LINKS: usize = 255;

/// A held lock. Dropping it releases the lock.
#[derive(Debug)]
pub struct Lock {
    _held: Flock<File>,
}

/// Serializes the verbs that rewrite the identity file. Two interleaved
/// rekeys share one staging path, so the second deletes the staged key
/// of the first while the first commits the vault to it. That destroys
/// the only key able to read the vault. One lock for rekey and passwd
/// both closes the window.
pub fn acquire_identity(identity_path: &Path) -> Result<Lock, Error> {
    acquire(
        &sibling_path(identity_path),
        &format!(
            "another safetybox rekey or passwd is running against {}: retry when it finishes",
            identity_path.display()
        ),
        // A missing directory means no identity was created here yet.
        // The lock is taken before the identity is loaded, so without
        // this a first run would complain about the lock file and not
        // point at init.
        || {
            hint::identity(identity::Error::NotFound {
                path: identity_path.to_owned(),
            })
        },
    )
}

/// Serializes migrate against another migrate of the same vault. Two
/// concurrent runs would otherwise both pass the format check, and the
/// loser would wait on the write lock and could time out with a raw
/// busy error.
pub fn acquire_migrate(vault_path: &Path) -> Result<Lock, Error> {
    acquire(
        &sibling_path(vault_path),
        &format!(
            "another safetybox migrate is running against {}: retry when it finishes",
            vault_path.display()
        ),
        || {
            hint::vault(vault::Error::NotFound {
                path: vault_path.to_owned(),
            })
        },
    )
}

/// Opens `lock_path` and takes an exclusive lock on it without
/// waiting. `busy` names the run that already holds it. `missing`
/// builds the error for a lock file whose directory does not exist.
fn acquire(lock_path: &Path, busy: &str, missing: impl FnOnce() -> Error) -> Result<Lock, Error> {
    let lock_path = sys::clean(lock_path);

    // O_NOFOLLOW refuses a symbolic link planted at the lock path,
    // which would otherwise redirect the file this creates. Planting
    // one needs write access to a private directory, so this is
    // hardening and not the fix for a reachable hole.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(LOCK_FILE_MODE)
        .open(&lock_path)
        .map_err(|err| match err.kind() {
            ErrorKind::NotFound => missing(),
            _ => Error::Message(format!(
                "open lock {}: {}",
                lock_path.display(),
                PathError::new("open", &lock_path, err)
            )),
        })?;

    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_, errno)| {
        let reason = sys::describe(&io::Error::from(errno));

        // Another process holding the lock is the one expected
        // failure. Anything else is the environment, such as a
        // filesystem without flock, and must not pose as a second run.
        if errno == Errno::EWOULDBLOCK {
            Error::Message(format!("{busy}: {reason}"))
        } else {
            Error::Message(format!("lock {}: {reason}", lock_path.display()))
        }
    })?;

    debug!("advisory lock acquired", "lock_path" => lock_path.to_string_lossy().as_ref());

    Ok(Lock { _held: held })
}

/// The lock path for `target`. Symbolic links are resolved, so two
/// spellings of one target lock the same file. Resolving needs the
/// target to exist. Before it does, the absolute path is used, and
/// failing that the cleaned one.
pub fn sibling_path(target: &Path) -> PathBuf {
    if let Ok(resolved) = eval_symlinks(target) {
        return sys::sibling(&resolved, ".lock");
    }

    if let Ok(absolute) = std::path::absolute(target) {
        return sys::sibling(&sys::clean(&absolute), ".lock");
    }

    sys::clean(&sys::sibling(target, ".lock"))
}

/// `path` with every symbolic link in it resolved. A relative path
/// stays relative unless a link leads to an absolute one. Every
/// component must exist.
fn eval_symlinks(path: &Path) -> io::Result<PathBuf> {
    let bytes = path.as_os_str().as_bytes();
    let mut resolved = PathBuf::from(if bytes.starts_with(b"/") { "/" } else { "" });
    let mut pending = components(path.as_os_str());
    let mut links = 0_usize;

    while let Some(component) = pending.pop_front() {
        if component == "." {
            continue;
        }

        if component == ".." {
            // What is resolved so far holds no links, so its parent is
            // the directory above it. A path that already climbs out
            // keeps climbing.
            let climbs = resolved.file_name().is_none() && !resolved.has_root();

            if climbs || resolved.ends_with("..") {
                resolved.push("..");
            } else {
                resolved.pop();
            }

            continue;
        }

        resolved.push(&component);

        if !fs::symlink_metadata(&resolved)?.file_type().is_symlink() {
            continue;
        }

        links += 1;

        if links > MAX_LINKS {
            return Err(io::Error::from_raw_os_error(libc::ELOOP));
        }

        let link = fs::read_link(&resolved)?;

        // The link replaces the component that named it. An absolute
        // link starts again from the root.
        if link.is_absolute() {
            resolved = PathBuf::from("/");
        } else {
            resolved.pop();
        }

        for part in components(link.as_os_str()).into_iter().rev() {
            pending.push_front(part);
        }
    }

    Ok(sys::clean(&resolved))
}

/// The non-empty segments of a path.
fn components(path: &OsStr) -> VecDeque<OsString> {
    path.as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| OsStr::from_bytes(segment).to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::symlink;
    use std::path::{Path, PathBuf};

    use super::{acquire, eval_symlinks, sibling_path};
    use crate::cmd::Error;

    fn missing() -> Error {
        Error::Message("fake missing directory".to_owned())
    }

    #[test]
    fn a_second_holder_is_refused_until_the_first_lets_go() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("identity.age.lock");

        let first = acquire(&path, "fake run in progress", missing).expect("first lock");
        let refused = acquire(&path, "fake run in progress", missing).expect_err("second lock");

        assert_eq!(
            refused.to_string(),
            "fake run in progress: resource temporarily unavailable"
        );

        drop(first);

        acquire(&path, "fake run in progress", missing).expect("lock after release");
        assert!(path.exists(), "the lock file stays in place");
    }

    #[test]
    fn a_missing_directory_and_a_planted_link_are_told_apart() {
        let directory = tempfile::tempdir().expect("temp dir");
        let nowhere = directory.path().join("nowhere").join("identity.age.lock");

        assert_eq!(
            acquire(&nowhere, "busy", missing)
                .expect_err("no directory")
                .to_string(),
            "fake missing directory"
        );

        let planted = directory.path().join("planted.lock");

        symlink(directory.path().join("elsewhere"), &planted).expect("symlink");

        assert_eq!(
            acquire(&planted, "busy", missing)
                .expect_err("a symlink")
                .to_string(),
            format!(
                "open lock {}: open {}: too many levels of symbolic links",
                planted.display(),
                planted.display()
            )
        );
        assert!(!directory.path().join("elsewhere").exists());
    }

    #[test]
    fn links_are_resolved_and_spellings_converge() {
        let directory = tempfile::tempdir().expect("temp dir");
        let root = fs::canonicalize(directory.path()).expect("canonical temp dir");
        let real = root.join("real");
        let target = real.join("identity.age");

        fs::create_dir(&real).expect("mkdir");
        fs::write(&target, "fake").expect("write");
        symlink(&real, root.join("absolute-link")).expect("symlink");
        symlink("real", root.join("relative-link")).expect("symlink");
        symlink("real/identity.age", root.join("file-link")).expect("symlink");

        for spelling in [
            "real/identity.age",
            "real/./identity.age",
            "real//identity.age",
            "real/../real/identity.age",
            "absolute-link/identity.age",
            "relative-link/identity.age",
            "relative-link/../real/identity.age",
            "file-link",
        ] {
            assert_eq!(
                eval_symlinks(&root.join(spelling)).expect(spelling),
                target,
                "{spelling}"
            );
            assert_eq!(
                sibling_path(&root.join(spelling)),
                real.join("identity.age.lock"),
                "{spelling}"
            );
        }

        assert!(eval_symlinks(&root.join("real/absent")).is_err());
    }

    #[test]
    fn a_target_that_does_not_exist_yet_locks_by_its_absolute_path() {
        let directory = tempfile::tempdir().expect("temp dir");
        let absent = directory.path().join("a").join("..").join("identity.age");

        assert_eq!(
            sibling_path(&absent),
            directory.path().join("identity.age.lock")
        );
    }

    #[test]
    fn a_relative_path_stays_relative() {
        // The manifest directory holds `src`, and tests run from it.
        assert_eq!(
            eval_symlinks(Path::new("./src/../src/lib.rs")).expect("resolve"),
            PathBuf::from("src/lib.rs")
        );
        assert_eq!(
            eval_symlinks(Path::new("src/..")).expect("resolve"),
            PathBuf::from(".")
        );
    }
}
