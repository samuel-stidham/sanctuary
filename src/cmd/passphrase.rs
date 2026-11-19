//! Where a passphrase comes from: `--passphrase-file`, or the no-echo
//! prompt. A passphrase never comes from an argument or from the
//! environment.

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use zeroize::Zeroizing;

use super::Error;
use super::prompt::prompt_once;
use crate::identity::Passphrase;
use crate::secret::read_all_wiping;
use crate::sys::{self, PathError, UNSAFE_BITS};

/// The passphrase for an existing identity, from the file or from one
/// prompt.
pub fn read(file: Option<&Path>, label: &str) -> Result<Passphrase, Error> {
    match given(file) {
        Some(file) => from_file(file),
        None => Ok(Passphrase::new(prompt_once(label, "passphrase")?)),
    }
}

/// The file flag, or nothing when it was passed empty. An empty path
/// means the flag was not passed, as it does for the vault and the
/// identity.
fn given(file: Option<&Path>) -> Option<&Path> {
    file.filter(|file| !file.as_os_str().is_empty())
}

/// The passphrase for new key material, from the file or from a prompt
/// and its confirmation.
pub fn read_new(file: Option<&Path>, label: &str) -> Result<Passphrase, Error> {
    if let Some(file) = given(file) {
        return from_file(file);
    }

    let passphrase = Passphrase::new(prompt_once(label, "passphrase")?);
    let confirmation = Passphrase::new(prompt_once("Confirm passphrase: ", "passphrase")?);

    if !passphrase.matches(&confirmation) {
        return Err(Error::Message("passphrases do not match".to_owned()));
    }

    Ok(passphrase)
}

/// Reads the passphrase from `path`, less its trailing newlines.
fn from_file(path: &Path) -> Result<Passphrase, Error> {
    let cleaned = sys::clean(path);
    let failed = |context: &str, operation: &'static str, err| {
        Error::Message(format!(
            "{context}: {}",
            PathError::new(operation, &cleaned, err)
        ))
    };

    // Open once and stat the descriptor, so the check and the read see
    // the same file.
    let file = File::open(&cleaned).map_err(|err| failed("open passphrase file", "open", err))?;
    let metadata = file
        .metadata()
        .map_err(|err| failed("stat passphrase file", "stat", err))?;

    // Only a regular file on disk is held to the permission check. A
    // fifo or pipe from process substitution is a passing stream, not
    // a secret at rest, so it is allowed.
    let mode = metadata.permissions().mode() & 0o777;

    if metadata.is_file() && mode & UNSAFE_BITS != 0 {
        return Err(Error::Message(format!(
            "passphrase file {} has mode {mode:04o}: run chmod 600 on it",
            path.display()
        )));
    }

    let mut content =
        read_all_wiping(&file).map_err(|err| failed("read passphrase file: read", "read", err))?;

    trim_line_end(&mut content);

    if content.is_empty() {
        return Err(Error::Message("passphrase file is empty".to_owned()));
    }

    Ok(Passphrase::new(content))
}

/// Drops the trailing newlines that editors and `echo` leave.
fn trim_line_end(content: &mut Zeroizing<Vec<u8>>) {
    while matches!(content.last(), Some(b'\r' | b'\n')) {
        content.pop();
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use zeroize::Zeroizing;

    use super::{from_file, trim_line_end};
    use crate::identity::Passphrase;

    fn passphrase(text: &str) -> Passphrase {
        Passphrase::new(Zeroizing::new(text.as_bytes().to_vec()))
    }

    #[test]
    fn trailing_newlines_are_trimmed_and_nothing_else() {
        for (content, want) in [
            ("fake\n", "fake"),
            ("fake\r\n", "fake"),
            ("fake\n\n\r\n", "fake"),
            (" fake \n", " fake "),
            ("fa\nke", "fa\nke"),
            ("\n", ""),
        ] {
            let mut bytes = Zeroizing::new(content.as_bytes().to_vec());

            trim_line_end(&mut bytes);

            assert_eq!(*bytes, want.as_bytes(), "{content:?}");
        }
    }

    #[test]
    fn a_file_is_read_and_checked() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("passphrase");
        let chmod = |mode| fs::set_permissions(&path, fs::Permissions::from_mode(mode));

        fs::write(&path, "fake-passphrase\r\n").expect("write");
        chmod(0o600).expect("chmod");

        assert!(
            from_file(&path)
                .expect("read")
                .matches(&passphrase("fake-passphrase"))
        );

        chmod(0o644).expect("chmod");
        assert_eq!(
            from_file(&path).expect_err("a loose file").to_string(),
            format!(
                "passphrase file {} has mode 0644: run chmod 600 on it",
                path.display()
            )
        );

        fs::write(&path, "\n").expect("write");
        chmod(0o600).expect("chmod");
        assert_eq!(
            from_file(&path).expect_err("an empty file").to_string(),
            "passphrase file is empty"
        );

        let missing = directory.path().join("missing");
        assert_eq!(
            from_file(&missing).expect_err("no file").to_string(),
            format!(
                "open passphrase file: open {}: no such file or directory",
                missing.display()
            )
        );
    }
}
