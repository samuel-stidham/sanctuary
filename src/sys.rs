//! Filesystem helpers the other modules share: lexical path cleaning
//! and file errors that read the same as the Go original's.
//!
//! An error message is behavior here. A script that greps stderr for
//! `no such file or directory` must find it whichever binary ran.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

/// Group and world permission bits.
pub const UNSAFE_BITS: u32 = 0o077;

/// A failed file operation: what was tried, on which path, and why.
/// It renders as `open /some/path: no such file or directory`.
#[derive(Debug)]
pub struct PathError {
    operation: &'static str,
    path: PathBuf,
    source: io::Error,
}

impl PathError {
    pub fn new(operation: &'static str, path: &Path, source: io::Error) -> Self {
        Self {
            operation,
            path: path.to_owned(),
            source,
        }
    }

    pub fn kind(&self) -> io::ErrorKind {
        self.source.kind()
    }
}

impl fmt::Display for PathError {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            out,
            "{} {}: {}",
            self.operation,
            self.path.display(),
            describe(&self.source)
        )
    }
}

impl std::error::Error for PathError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// The reason behind an I/O error, without the `(os error N)` suffix
/// and starting in lower case: `permission denied`.
///
/// The text is the C library's, which is what the Go original's own
/// table follows. `resource temporarily unavailable` reads the same
/// from both.
pub fn describe(err: &io::Error) -> String {
    let Some(code) = err.raw_os_error() else {
        return err.to_string();
    };

    let rendered = err.to_string();
    let text = rendered
        .strip_suffix(&format!(" (os error {code})"))
        .unwrap_or(&rendered);

    let mut letters = text.chars();

    match letters.next() {
        // An acronym keeps its case: `RFS specific error`.
        Some(_) if letters.clone().next().is_some_and(char::is_uppercase) => text.to_owned(),
        Some(first) => first.to_lowercase().chain(letters).collect(),
        None => String::new(),
    }
}

/// The shortest path naming the same file as `path`, worked out from
/// the text alone. Repeated separators collapse, `.` segments go, and
/// a `..` cancels the segment before it. An empty path becomes `.`.
pub fn clean(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    let rooted = bytes.first() == Some(&b'/');
    let mut kept: Vec<&[u8]> = Vec::new();

    for segment in bytes.split(|byte| *byte == b'/') {
        match segment {
            b"" | b"." => {}
            b".." => match kept.last() {
                Some(last) if *last != b".." => {
                    kept.pop();
                }
                // Nothing sits above the root, so the segment goes.
                _ if rooted => {}
                _ => kept.push(segment),
            },
            _ => kept.push(segment),
        }
    }

    let mut cleaned = Vec::with_capacity(bytes.len());

    if rooted {
        cleaned.push(b'/');
    }

    cleaned.extend(kept.join(&b'/'));

    if cleaned.is_empty() {
        cleaned.push(b'.');
    }

    PathBuf::from(OsString::from_vec(cleaned))
}

/// The directory holding `path`, which for a bare file name is `.`.
pub fn parent(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_owned(),
        Some(_) => PathBuf::from("."),
        None => path.to_owned(),
    }
}

/// `path` with `suffix` appended to its file name.
pub fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();

    name.push(suffix);

    PathBuf::from(name)
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::path::{Path, PathBuf};

    use super::{PathError, clean, describe, parent, sibling};

    #[test]
    fn clean_matches_the_lexical_rules() {
        let cases = [
            ("", "."),
            (".", "."),
            ("/", "/"),
            ("//", "/"),
            ("a", "a"),
            ("a/", "a"),
            ("a//b", "a/b"),
            ("a/./b", "a/b"),
            ("a/../b", "b"),
            ("a/b/..", "a"),
            ("a/..", "."),
            ("../a", "../a"),
            ("../../a", "../../a"),
            ("a/../../b", "../b"),
            ("/..", "/"),
            ("/../a", "/a"),
            ("/a/../..", "/"),
            ("/tmp//vault.db", "/tmp/vault.db"),
            ("./vault.db", "vault.db"),
        ];

        for (path, want) in cases {
            assert_eq!(clean(Path::new(path)), PathBuf::from(want), "{path:?}");
        }
    }

    #[test]
    fn parent_of_a_bare_name_is_the_working_directory() {
        assert_eq!(parent(Path::new("vault.db")), PathBuf::from("."));
        assert_eq!(parent(Path::new("a/vault.db")), PathBuf::from("a"));
        assert_eq!(parent(Path::new("/vault.db")), PathBuf::from("/"));
        assert_eq!(parent(Path::new("/")), PathBuf::from("/"));
    }

    #[test]
    fn sibling_appends_to_the_file_name() {
        assert_eq!(
            sibling(Path::new("/a/vault.db"), "-wal"),
            PathBuf::from("/a/vault.db-wal")
        );
    }

    #[test]
    fn errors_read_like_the_reference() {
        let missing = io::Error::from_raw_os_error(2);

        assert_eq!(describe(&missing), "no such file or directory");
        assert_eq!(
            PathError::new("open", Path::new("/a/b"), missing).to_string(),
            "open /a/b: no such file or directory"
        );
        assert_eq!(
            describe(&io::Error::from_raw_os_error(13)),
            "permission denied"
        );
        assert_eq!(describe(&io::Error::other("made up")), "made up");

        assert_eq!(
            describe(&io::Error::from_raw_os_error(73)),
            "RFS specific error"
        );

        // These two read differently in the kernel's own headers.
        assert_eq!(
            describe(&io::Error::from_raw_os_error(11)),
            "resource temporarily unavailable"
        );
        assert_eq!(
            describe(&io::Error::from_raw_os_error(40)),
            "too many levels of symbolic links"
        );
    }
}
