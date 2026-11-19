//! Where the vault and the identity live.
//!
//! Precedence is flag, then environment, then the XDG default. An empty
//! flag or variable counts as unset. The directory is named after the
//! product, not the command, so this build and the Go original open the
//! same vault.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::Error;
use crate::sys;

const ENV_VAULT: &str = "SAFETYBOX_VAULT";
const ENV_IDENTITY: &str = "SAFETYBOX_IDENTITY";

/// The directory both files default into, under their XDG base.
const DIRECTORY: &str = "safetybox";

/// Reads one environment variable.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<OsString>;

/// Reads the process environment.
pub fn process_env(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// The vault path: `--vault`, `SAFETYBOX_VAULT`, then
/// `$XDG_DATA_HOME/safetybox/vault.db`.
pub fn vault(flag: Option<&Path>, env: Env<'_>) -> Result<PathBuf, Error> {
    resolve(
        flag,
        env,
        ENV_VAULT,
        "XDG_DATA_HOME",
        ".local/share",
        "vault.db",
    )
    .ok_or(Error::NoHome { what: "vault" })
}

/// The identity path: `--identity`, `SAFETYBOX_IDENTITY`, then
/// `$XDG_CONFIG_HOME/safetybox/identity.age`.
pub fn identity(flag: Option<&Path>, env: Env<'_>) -> Result<PathBuf, Error> {
    resolve(
        flag,
        env,
        ENV_IDENTITY,
        "XDG_CONFIG_HOME",
        ".config",
        "identity.age",
    )
    .ok_or(Error::NoHome { what: "identity" })
}

/// Picks the path and cleans it.
///
/// Cleaning here is what keeps one run on one spelling. The identity
/// and the vault are read and written at the cleaned path, and their
/// siblings, such as the staged key of a rekey, are named from the
/// path this returns. Were this one left uncleaned, a `..` after a
/// directory that does not exist would send the two to different
/// places, and a rekey would commit the vault and then fail the swap.
fn resolve(
    flag: Option<&Path>,
    env: Env<'_>,
    variable: &str,
    xdg_variable: &str,
    home_default: &str,
    file: &str,
) -> Option<PathBuf> {
    let set = |name: &str| env(name).filter(|value| !value.is_empty());

    if let Some(flag) = flag.filter(|path| !path.as_os_str().is_empty()) {
        return Some(sys::clean(flag));
    }

    if let Some(from_env) = set(variable) {
        return Some(sys::clean(Path::new(&from_env)));
    }

    let base = match set(xdg_variable) {
        Some(base) => PathBuf::from(base),
        None => PathBuf::from(set("HOME")?).join(home_default),
    };

    Some(sys::clean(&base.join(DIRECTORY).join(file)))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    use super::{identity, vault};

    /// A case name, the flag, the environment, and the path wanted.
    type Case<'a> = (&'a str, Option<&'a str>, &'a [(&'a str, &'a str)], &'a str);

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |name| {
            vars.iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.into())
        }
    }

    #[test]
    fn every_source_is_cleaned() {
        let unclean = [
            ("SAFETYBOX_VAULT", "/from/env/./x/../vault.db"),
            ("SAFETYBOX_IDENTITY", "/from/env//identity.age"),
        ];
        let defaults = [
            ("XDG_DATA_HOME", "/from/./xdg//x/.."),
            ("XDG_CONFIG_HOME", "/from/xdg/config/"),
            ("HOME", "/fake/home"),
        ];
        let home_only = [("HOME", "/fake/./home/")];

        assert_eq!(
            vault(Some(Path::new("/from/flag/x/../vault.db")), &env(&[])).expect("flag"),
            PathBuf::from("/from/flag/vault.db")
        );
        assert_eq!(
            vault(Some(Path::new("./vault.db")), &env(&[])).expect("relative flag"),
            PathBuf::from("vault.db")
        );
        assert_eq!(
            vault(None, &env(&unclean)).expect("env"),
            PathBuf::from("/from/env/vault.db")
        );
        assert_eq!(
            identity(None, &env(&unclean)).expect("env"),
            PathBuf::from("/from/env/identity.age")
        );
        assert_eq!(
            vault(None, &env(&defaults)).expect("xdg"),
            PathBuf::from("/from/xdg/safetybox/vault.db")
        );
        assert_eq!(
            identity(None, &env(&defaults)).expect("xdg"),
            PathBuf::from("/from/xdg/config/safetybox/identity.age")
        );
        assert_eq!(
            identity(None, &env(&home_only)).expect("home"),
            PathBuf::from("/fake/home/.config/safetybox/identity.age")
        );
    }

    // Go: TestResolveVaultPathPrecedence
    #[test]
    fn vault_path_precedence() {
        let everything = [
            ("SAFETYBOX_VAULT", "/from/env/vault.db"),
            ("XDG_DATA_HOME", "/from/xdg"),
            ("HOME", "/fake/home"),
        ];

        let cases: [Case<'_>; 6] = [
            (
                "flag wins",
                Some("/from/flag/vault.db"),
                &everything,
                "/from/flag/vault.db",
            ),
            ("env beats xdg", None, &everything, "/from/env/vault.db"),
            (
                "an empty flag is unset",
                Some(""),
                &everything,
                "/from/env/vault.db",
            ),
            (
                "xdg default",
                None,
                &everything[1..],
                "/from/xdg/safetybox/vault.db",
            ),
            (
                "home default",
                None,
                &everything[2..],
                "/fake/home/.local/share/safetybox/vault.db",
            ),
            (
                "empty variables are unset",
                None,
                &[
                    ("SAFETYBOX_VAULT", ""),
                    ("XDG_DATA_HOME", ""),
                    ("HOME", "/fake/home"),
                ],
                "/fake/home/.local/share/safetybox/vault.db",
            ),
        ];

        for (name, flag, vars, want) in cases {
            let got = vault(flag.map(Path::new), &env(vars)).expect(name);

            assert_eq!(got, PathBuf::from(want), "{name}");
        }
    }

    // Go: TestResolveIdentityPathPrecedence
    #[test]
    fn identity_path_precedence() {
        let everything = [
            ("SAFETYBOX_IDENTITY", "/from/env/identity.age"),
            ("XDG_CONFIG_HOME", "/from/xdg"),
            ("HOME", "/fake/home"),
        ];

        let cases: [Case<'_>; 4] = [
            (
                "flag wins",
                Some("/from/flag/identity.age"),
                &everything,
                "/from/flag/identity.age",
            ),
            ("env beats xdg", None, &everything, "/from/env/identity.age"),
            (
                "xdg default",
                None,
                &everything[1..],
                "/from/xdg/safetybox/identity.age",
            ),
            (
                "home default",
                None,
                &everything[2..],
                "/fake/home/.config/safetybox/identity.age",
            ),
        ];

        for (name, flag, vars, want) in cases {
            let got = identity(flag.map(Path::new), &env(vars)).expect(name);

            assert_eq!(got, PathBuf::from(want), "{name}");
        }
    }

    #[test]
    fn no_home_is_an_error_that_names_the_path() {
        let err = vault(None, &env(&[])).expect_err("no home");
        assert_eq!(err.to_string(), "resolve vault path: $HOME is not defined");

        let err = identity(None, &env(&[("HOME", "")])).expect_err("empty home");
        assert_eq!(
            err.to_string(),
            "resolve identity path: $HOME is not defined"
        );
    }
}
