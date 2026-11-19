//! The reveal verb: the one place plaintext is printed.
//!
//! One name prints one JSON object. Several names, `--env`, or
//! `--prefix` select a batch that decrypts with a single passphrase
//! read. `--format sh` or `fish` emits assignment lines ready to source
//! into a shell session.

use std::io::{self, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use super::cli::{Globals, NAME};
use super::decrypt::for_each_decrypted;
use super::envname::{is_reserved, is_shell_identifier};
use super::{Error, hint, open_vault};
use crate::json::{Json, Layout};
use crate::quote::quote;
use crate::secret::Value;
use crate::sys;
use crate::timestamp::Time;
use crate::vault::{Entry, EntryFilter, Vault};
use crate::warn;

pub const FORMAT_JSON: &str = "json";
const FORMAT_SH: &str = "sh";
const FORMAT_FISH: &str = "fish";

/// The reveal flags. An empty prefix means no prefix was asked for.
pub struct Flags<'a> {
    pub env: bool,
    pub prefix: &'a str,
    pub format: &'a str,
}

/// The shell dialect of assignment output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Sh,
    Fish,
}

impl Dialect {
    fn name(self) -> &'static str {
        match self {
            Self::Sh => FORMAT_SH,
            Self::Fish => FORMAT_FISH,
        }
    }
}

/// One revealed secret. This is the only output shape that carries
/// plaintext.
struct Revealed {
    name: String,
    env_name: Option<String>,
    version: i64,
    expires_at: Option<Time>,
    expired: bool,
    value: Value,
}

pub fn run(globals: &Globals, names: &[String], flags: &Flags<'_>) -> Result<(), Error> {
    let dialect = validate(names, flags, globals.json)?;
    let explicit = !names.is_empty();
    let (entries, recipient) = collect(globals, names, flags)?;

    let mut revealed = Vec::with_capacity(entries.len());
    let mut skipped = Vec::new();

    // A filter that matches nothing never touches the identity, so an
    // empty result costs no passphrase prompt and no key derivation.
    if !entries.is_empty() {
        // A secret asked for by name fails loud on a metadata mismatch,
        // as get does. A filter skips the mismatching secret and warns.
        skipped = for_each_decrypted(
            globals,
            &recipient,
            entries,
            explicit,
            |entry, expired, value| {
                revealed.push(Revealed {
                    name: entry.name.clone(),
                    // An empty env name is no env name.
                    env_name: entry.env_name.clone().filter(|name| !name.is_empty()),
                    version: entry.version,
                    expires_at: entry.expires_at,
                    expired,
                    value,
                });

                Ok(())
            },
        )?;
    }

    if let Some(dialect) = dialect {
        return print_assignments(&revealed, &skipped, dialect, explicit);
    }

    // A single name keeps the one-object shape, so
    // `reveal <name> --json | jq -r .value` stays stable.
    let mut payload = match revealed.as_slice() {
        [only] if names.len() == 1 => json_of(only),
        many => Json::Array(many.iter().map(json_of).collect()),
    };

    let layout = if globals.json {
        Layout::Compact
    } else {
        Layout::Pretty
    };

    let mut rendered = Zeroizing::new(payload.render(layout));

    payload.wipe();
    rendered.push('\n');

    write_stdout(rendered.as_bytes()).map_err(Error::Output)
}

/// Refuses a contradictory selection before any vault or identity work
/// happens. It returns the shell dialect, or nothing for JSON.
fn validate(names: &[String], flags: &Flags<'_>, compact: bool) -> Result<Option<Dialect>, Error> {
    let filtering = flags.env || !flags.prefix.is_empty();
    let refuse = |message: &str| Err(Error::Message(message.to_owned()));

    if !names.is_empty() && filtering {
        return refuse("pass names or --env/--prefix filters, not both");
    }

    if names.is_empty() && !filtering {
        return refuse("pass at least one name, or select a set with --env or --prefix");
    }

    let dialect = match flags.format {
        FORMAT_JSON => return Ok(None),
        FORMAT_SH => Dialect::Sh,
        FORMAT_FISH => Dialect::Fish,
        other => {
            return Err(Error::Message(format!(
                "--format {} is not json, sh, or fish",
                quote(other)
            )));
        }
    };

    if compact {
        return refuse("--json applies to json output, drop it or drop --format");
    }

    Ok(Some(dialect))
}

/// Selects the secrets to decrypt, and reads the stored recipient for
/// the decrypt path to verify. Names resolve one by one, so a missing
/// or deleted name fails loud. A filter selects whatever matches, and
/// matching nothing is fine.
fn collect(
    globals: &Globals,
    names: &[String],
    flags: &Flags<'_>,
) -> Result<(Vec<Entry>, String), Error> {
    let vault = open_vault(globals)?;

    let recipient = vault
        .recipient()
        .map_err(|err| hint::vault_in("read stored recipient", err))?;

    let entries = if names.is_empty() {
        vault
            .entries(EntryFilter {
                prefix: flags.prefix,
                env_named: flags.env,
            })
            .map_err(hint::vault)?
    } else {
        entries_by_name(&vault, names)?
    };

    Ok((entries, recipient))
}

fn entries_by_name(vault: &Vault, names: &[String]) -> Result<Vec<Entry>, Error> {
    names
        .iter()
        .map(|name| {
            let resolved = vault.newest_enabled(name).map_err(hint::vault)?;

            Ok(Entry {
                name: resolved.secret.name,
                env_name: resolved.secret.env_name,
                version: resolved.version.number,
                expires_at: resolved.secret.expires_at,
                envelope: resolved.envelope,
            })
        })
        .collect()
}

/// One secret as a JSON object. A value JSON cannot carry byte for
/// byte is base64-encoded and marked, with a warning. A plain encoder
/// would swap each invalid byte for U+FFFD, and the value read back
/// would differ from what the vault holds.
fn json_of(revealed: &Revealed) -> Json {
    let mut members = vec![("name", Json::from(revealed.name.clone()))];

    if let Some(env_name) = &revealed.env_name {
        members.push(("envName", env_name.clone().into()));
    }

    members.push(("version", revealed.version.into()));

    if let Some(expires_at) = revealed.expires_at {
        members.push(("expiresAt", expires_at.to_output().into()));
    }

    members.push(("expired", revealed.expired.into()));

    // This is the one deliberate plaintext display.
    let plaintext = revealed.value.expose();

    match std::str::from_utf8(plaintext) {
        Ok(text) => members.push(("value", text.to_owned().into())),
        Err(_) => {
            warn!(
                "secret is not valid UTF-8, its JSON value is base64-encoded, use exec for raw bytes",
                "name" => revealed.name.as_str(),
            );

            members.push(("encoding", "base64".into()));
            members.push(("value", STANDARD.encode(plaintext).into()));
        }
    }

    Json::Object(members)
}

/// Why a secret cannot become an assignment line, or nothing when it
/// can.
fn unusable(revealed: &Revealed) -> Option<String> {
    let Some(env_name) = &revealed.env_name else {
        return Some("has no env name".to_owned());
    };

    if !is_shell_identifier(env_name) {
        return Some(format!(
            "env name {} is not a shell identifier",
            quote(env_name)
        ));
    }

    // Emitting a reserved name would let a sourced batch rewrite PATH
    // or preload a library into the sourcing shell. Leaving the line
    // out keeps the shell's own value.
    if is_reserved(env_name) {
        return Some(format!(
            "env name {} is reserved, so a shell must not take it from a secret",
            quote(env_name)
        ));
    }

    if revealed.value.expose().contains(&0) {
        return Some("value contains a NUL byte, which a shell variable cannot hold".to_owned());
    }

    None
}

/// Writes one assignment line per usable secret.
///
/// With names, one unusable secret fails the whole batch before
/// anything is written, as a missing name does. A filter skips it with
/// a warning, so a sourced batch never drops a secret in silence. A
/// repeated env name warns, because the last assignment wins in the
/// sourcing shell.
fn print_assignments(
    revealed: &[Revealed],
    skipped: &[Entry],
    dialect: Dialect,
    explicit: bool,
) -> Result<(), Error> {
    if explicit {
        let refused: Vec<String> = revealed
            .iter()
            .filter_map(|one| Some(format!("{} {}", quote(&one.name), unusable(one)?)))
            .collect();

        if !refused.is_empty() {
            return Err(Error::Message(format!(
                "cannot emit {} assignments: {} (set an env name with `{NAME} set <name> \
                 --env-name NAME`)",
                dialect.name(),
                refused.join("; ")
            )));
        }
    }

    // Which secret supplied each env name, in the order written.
    let mut delivered: Vec<(&str, &str)> = Vec::with_capacity(revealed.len());

    // The names of secrets withheld for their value alone. A reserved
    // name is left out, so the shell keeps its own value for it.
    let mut withheld: Vec<&str> = Vec::new();

    for one in revealed {
        if let Some(reason) = unusable(one) {
            warn!(
                "secret skipped",
                "name" => one.name.as_str(),
                "reason" => reason,
            );

            if let Some(env_name) = one.env_name.as_deref()
                && is_shell_identifier(env_name)
                && !is_reserved(env_name)
            {
                withheld.push(env_name);
            }

            continue;
        }

        let Some(env_name) = one.env_name.as_deref() else {
            continue;
        };

        if let Some((_, previous)) = delivered.iter().rev().find(|(name, _)| *name == env_name) {
            warn!(
                "env name collision, the later secret overrides the earlier value",
                "env_name" => env_name,
                "name" => one.name.as_str(),
                "previous" => *previous,
            );
        }

        delivered.push((env_name, &one.name));

        let line = assignment_line(dialect, env_name, one.value.expose());

        write_stdout(&line).map_err(|err| shell_write_failed("write shell assignment", &err))?;
    }

    let erased = skipped
        .iter()
        .filter_map(|entry| entry.env_name.as_deref())
        .chain(withheld);

    erase_skipped(erased, &delivered, dialect)
}

/// Writes an erase line for every variable a skipped secret was meant
/// to supply.
///
/// Leaving the assignment out is not enough. A shell that sources this
/// output keeps whatever value it already held under that name, so a
/// stale credential stands in for the one that was withheld. Erasing
/// makes the variable absent, which the caller can test for.
///
/// A name another secret supplied is left alone, since that value is
/// current. A reserved name is left alone too: erasing PATH in the
/// sourcing shell would be as harmful as setting it.
fn erase_skipped<'a>(
    skipped: impl Iterator<Item = &'a str>,
    delivered: &[(&str, &str)],
    dialect: Dialect,
) -> Result<(), Error> {
    let mut erased: Vec<&str> = Vec::new();

    for env_name in skipped {
        if !is_shell_identifier(env_name)
            || is_reserved(env_name)
            || delivered.iter().any(|(name, _)| *name == env_name)
            || erased.contains(&env_name)
        {
            continue;
        }

        erased.push(env_name);

        let line = format!("{}\n", erase_line(dialect, env_name));

        write_stdout(line.as_bytes())
            .map_err(|err| shell_write_failed("write shell erase", &err))?;

        warn!(
            "variable erased, so a sourcing shell cannot keep a stale value",
            "env_name" => env_name,
        );
    }

    Ok(())
}

fn shell_write_failed(context: &str, err: &io::Error) -> Error {
    Error::Message(format!(
        "{context}: write /dev/stdout: {}",
        sys::describe(err)
    ))
}

/// The removal of one variable, in the dialect asked for.
fn erase_line(dialect: Dialect, name: &str) -> String {
    match dialect {
        Dialect::Sh => format!("unset {name}"),
        Dialect::Fish => format!("set --erase {name}"),
    }
}

/// One assignment line with its newline, in the dialect asked for.
/// Single quotes carry newlines in both dialects, so a multiline value
/// survives sourcing. The line holds plaintext and wipes itself.
fn assignment_line(dialect: Dialect, name: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut line = Zeroizing::new(Vec::with_capacity(name.len() + value.len() + 16));

    match dialect {
        Dialect::Sh => {
            line.extend_from_slice(b"export ");
            line.extend_from_slice(name.as_bytes());
            line.push(b'=');
        }
        Dialect::Fish => {
            line.extend_from_slice(b"set -gx ");
            line.extend_from_slice(name.as_bytes());
            line.push(b' ');
        }
    }

    line.push(b'\'');

    for byte in value {
        match (dialect, byte) {
            // In a POSIX shell a single quote closes the string,
            // escapes itself, and reopens it.
            (Dialect::Sh, b'\'') => line.extend_from_slice(b"'\\''"),
            // In fish, backslash and single quote are the only
            // characters read specially inside single quotes.
            (Dialect::Fish, b'\\') => line.extend_from_slice(b"\\\\"),
            (Dialect::Fish, b'\'') => line.extend_from_slice(b"\\'"),
            _ => line.push(*byte),
        }
    }

    line.extend_from_slice(b"'\n");

    line
}

/// Writes to stdout and reports the failure. A dropped error would let
/// a full disk or a broken pipe exit 0 with truncated output.
fn write_stdout(bytes: &[u8]) -> io::Result<()> {
    let mut stdout = io::stdout().lock();

    stdout.write_all(bytes)?;
    stdout.flush()
}

#[cfg(test)]
mod tests {
    use super::{Dialect, Flags, Revealed, assignment_line, erase_line, unusable, validate};
    use crate::secret::Value;

    fn line(dialect: Dialect, value: &[u8]) -> Vec<u8> {
        assignment_line(dialect, "FAKE_NAME", value).to_vec()
    }

    fn revealed(env_name: Option<&str>, value: &[u8]) -> Revealed {
        Revealed {
            name: "api/one".to_owned(),
            env_name: env_name.map(str::to_owned),
            version: 1,
            expires_at: None,
            expired: false,
            value: Value::new(value),
        }
    }

    // Go: TestQuoteSh
    #[test]
    fn sh_quoting() {
        for (value, want) in [
            ("plain", "export FAKE_NAME='plain'\n"),
            ("", "export FAKE_NAME=''\n"),
            ("it's", "export FAKE_NAME='it'\\''s'\n"),
            ("a\\b", "export FAKE_NAME='a\\b'\n"),
            ("two\nlines", "export FAKE_NAME='two\nlines'\n"),
            ("$HOME `id` \"q\"", "export FAKE_NAME='$HOME `id` \"q\"'\n"),
        ] {
            assert_eq!(
                line(Dialect::Sh, value.as_bytes()),
                want.as_bytes(),
                "{value:?}"
            );
        }
    }

    // Go: TestQuoteFish
    #[test]
    fn fish_quoting() {
        for (value, want) in [
            ("plain", "set -gx FAKE_NAME 'plain'\n"),
            ("", "set -gx FAKE_NAME ''\n"),
            ("it's", "set -gx FAKE_NAME 'it\\'s'\n"),
            ("a\\b", "set -gx FAKE_NAME 'a\\\\b'\n"),
            ("a\\'b", "set -gx FAKE_NAME 'a\\\\\\'b'\n"),
            ("two\nlines", "set -gx FAKE_NAME 'two\nlines'\n"),
        ] {
            assert_eq!(
                line(Dialect::Fish, value.as_bytes()),
                want.as_bytes(),
                "{value:?}"
            );
        }
    }

    #[test]
    fn bytes_that_are_not_text_pass_through_unchanged() {
        assert_eq!(
            line(Dialect::Sh, &[0xff, b'\'', 0xfe]),
            b"export FAKE_NAME='\xff'\\''\xfe'\n"
        );
    }

    #[test]
    fn erase_lines() {
        assert_eq!(erase_line(Dialect::Sh, "FAKE_NAME"), "unset FAKE_NAME");
        assert_eq!(
            erase_line(Dialect::Fish, "FAKE_NAME"),
            "set --erase FAKE_NAME"
        );
    }

    #[test]
    fn what_a_shell_cannot_take() {
        assert_eq!(unusable(&revealed(Some("FAKE_NAME"), b"fake-value")), None);
        assert_eq!(
            unusable(&revealed(None, b"fake-value")).as_deref(),
            Some("has no env name")
        );
        assert_eq!(
            unusable(&revealed(Some("not-valid"), b"fake-value")).as_deref(),
            Some("env name \"not-valid\" is not a shell identifier")
        );
        assert_eq!(
            unusable(&revealed(Some("PATH"), b"fake-value")).as_deref(),
            Some("env name \"PATH\" is reserved, so a shell must not take it from a secret")
        );
        assert_eq!(
            unusable(&revealed(Some("FAKE_NAME"), b"fake\0value")).as_deref(),
            Some("value contains a NUL byte, which a shell variable cannot hold")
        );
    }

    #[test]
    fn contradictory_requests_are_refused() {
        let names = ["api/one".to_owned()];
        let flags = |env, prefix, format| Flags {
            env,
            prefix,
            format,
        };
        let refusal = |names: &[String], flags: &Flags<'_>, compact| {
            validate(names, flags, compact)
                .expect_err("a refusal")
                .to_string()
        };

        assert_eq!(
            validate(&names, &flags(false, "", "json"), true).expect("json"),
            None
        );
        assert_eq!(
            validate(&[], &flags(true, "", "sh"), false).expect("sh"),
            Some(Dialect::Sh)
        );
        assert_eq!(
            validate(&[], &flags(false, "api", "fish"), false).expect("fish"),
            Some(Dialect::Fish)
        );

        assert_eq!(
            refusal(&names, &flags(true, "", "json"), false),
            "pass names or --env/--prefix filters, not both"
        );
        assert_eq!(
            refusal(&[], &flags(false, "", "json"), false),
            "pass at least one name, or select a set with --env or --prefix"
        );
        assert_eq!(
            refusal(&names, &flags(false, "", "sh"), true),
            "--json applies to json output, drop it or drop --format"
        );
        assert_eq!(
            refusal(&names, &flags(false, "", "yaml"), true),
            "--format \"yaml\" is not json, sh, or fish"
        );
        assert_eq!(
            refusal(&names, &flags(false, "", ""), false),
            "--format \"\" is not json, sh, or fish"
        );
    }
}
