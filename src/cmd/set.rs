//! The set verb: a new version of a secret.

use std::io::{self, IsTerminal};
use std::os::fd::AsFd;
use std::path::Path;

use zeroize::Zeroizing;

use super::cli::Globals;
use super::envname::{is_reserved, is_shell_identifier};
use super::prompt::prompt_once;
use super::{Error, hint, open_vault, print_json, recipient};
use crate::envelope::{self, Bound};
use crate::json::Json;
use crate::quote::quote;
use crate::secret::{Unbuffered, Value, read_all_wiping};
use crate::sys::PathError;
use crate::timestamp::Time;
use crate::vault::{Change, SealRequest, SetOptions};

/// The set flags. `None` means the flag was not passed, which is not
/// the same as passing it empty.
pub struct Flags<'a> {
    pub env_name: Option<&'a str>,
    pub expires: Option<&'a str>,
    pub revoke_previous: bool,
}

pub fn run(globals: &Globals, name: &str, flags: &Flags<'_>) -> Result<(), Error> {
    let options = options_from(flags)?;
    let value = Value::from(read_value(name)?);
    let mut vault = open_vault(globals)?;

    // The recipient arrives from inside the writing transaction, so it
    // cannot be one a concurrent rekey has already retired. Sealing
    // needs the public recipient alone, which is why writing a secret
    // never asks for the passphrase.
    let result = vault
        .append_version(name, &options, |request: SealRequest<'_>| {
            let recipient = recipient::parse_stored(request.recipient)?;

            let bound = Bound::new(request.env_name, request.expires_at);

            envelope::seal(&recipient, request.address, &bound, &value)
                .map_err(|err| err.to_string())
        })
        .map_err(hint::vault)?;

    let mut output = vec![
        ("name", Json::from(result.secret.name)),
        ("version", result.version.number.into()),
        ("state", result.version.state.as_str().into()),
    ];

    if let Some(env_name) = result.secret.env_name {
        output.push(("envName", env_name.into()));
    }

    if let Some(expires_at) = result.secret.expires_at {
        output.push(("expiresAt", expires_at.to_output().into()));
    }

    output.push(("revokedPrevious", result.revoked.into()));

    print_json(globals, &Json::Object(output))
}

/// Turns the flags into what the vault should change. An empty
/// `--env-name` clears the env name and an empty `--expires` clears the
/// expiry.
fn options_from(flags: &Flags<'_>) -> Result<SetOptions, Error> {
    let env_name = match flags.env_name {
        None => Change::Keep,
        Some("") => Change::Clear,
        Some(env_name) => {
            // An env name must be a valid shell identifier, so exec and
            // `reveal --format` can emit it as a variable name.
            if !is_shell_identifier(env_name) {
                return Err(Error::Message(format!(
                    "--env-name {} is not a valid shell identifier",
                    quote(env_name)
                )));
            }

            // A valid identifier is not automatically a safe one. PATH,
            // LD_PRELOAD, and their kin decide what code the child
            // runs, so a secret may not carry them. Refuse here, where
            // the message can reach the person typing it.
            if is_reserved(env_name) {
                return Err(Error::Message(format!(
                    "--env-name {} is reserved: a shell or the dynamic loader reads it to \
                     decide what code to run, so a secret cannot supply it",
                    quote(env_name)
                )));
            }

            Change::Set(env_name.to_owned())
        }
    };

    let expires_at = match flags.expires {
        None => Change::Keep,
        Some("") => Change::Clear,
        Some(expires) => Change::Set(parse_expiry(expires)?),
    };

    Ok(SetOptions {
        env_name,
        expires_at,
        revoke_previous: flags.revoke_previous,
    })
}

/// Reads an expiry as RFC 3339, or as a bare date meaning midnight UTC
/// of that day.
fn parse_expiry(raw: &str) -> Result<Time, Error> {
    Time::parse_rfc3339(raw)
        .or_else(|| Time::parse_date(raw))
        .map(Time::to_utc)
        .ok_or_else(|| {
            Error::Message(format!(
                "parse --expires {}: use RFC3339 or YYYY-MM-DD",
                quote(raw)
            ))
        })
}

/// Reads the plaintext from a no-echo prompt on a terminal, or from
/// stdin otherwise. A value never comes from an argument.
fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let stdin = io::stdin();

    if stdin.is_terminal() {
        return prompt_once(&format!("Value for {name}: "), "value");
    }

    // The descriptor is read directly. The standard handle would copy
    // the value into its own buffer first, and nothing wipes that one.
    let mut value = read_all_wiping(Unbuffered(stdin.as_fd())).map_err(|err| {
        Error::Message(format!(
            "read value from stdin: read: {}",
            PathError::new("read", Path::new("/dev/stdin"), err)
        ))
    })?;

    trim_one_line_end(&mut value);

    if value.is_empty() {
        return Err(Error::Message("value must not be empty".to_owned()));
    }

    Ok(value)
}

/// Strips one trailing newline, so `echo value | set` stores what was
/// typed. Deeper newlines are kept.
fn trim_one_line_end(value: &mut Zeroizing<Vec<u8>>) {
    if value.last() == Some(&b'\n') {
        value.pop();
    }

    if value.last() == Some(&b'\r') {
        value.pop();
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{Flags, options_from, parse_expiry, trim_one_line_end};
    use crate::vault::Change;

    fn flags<'a>(env_name: Option<&'a str>, expires: Option<&'a str>) -> Flags<'a> {
        Flags {
            env_name,
            expires,
            revoke_previous: false,
        }
    }

    #[test]
    fn one_line_end_is_trimmed() {
        for (value, want) in [
            ("fake\n", "fake"),
            ("fake\r\n", "fake"),
            ("fake\n\n", "fake\n"),
            ("fake\r", "fake"),
            ("fake\n\r", "fake\n"),
            ("fa\nke", "fa\nke"),
            ("\n", ""),
            ("fake", "fake"),
        ] {
            let mut bytes = Zeroizing::new(value.as_bytes().to_vec());

            trim_one_line_end(&mut bytes);

            assert_eq!(*bytes, want.as_bytes(), "{value:?}");
        }
    }

    #[test]
    fn an_expiry_is_a_timestamp_or_a_date() {
        for (raw, want) in [
            ("2030-01-02T03:04:05Z", "2030-01-02T03:04:05Z"),
            ("2030-01-02T03:04:05+02:00", "2030-01-02T01:04:05Z"),
            ("2030-01-02", "2030-01-02T00:00:00Z"),
        ] {
            assert_eq!(parse_expiry(raw).expect(raw).to_output(), want, "{raw}");
        }

        assert_eq!(
            parse_expiry("tomorrow")
                .expect_err("not a time")
                .to_string(),
            "parse --expires \"tomorrow\": use RFC3339 or YYYY-MM-DD"
        );
    }

    #[test]
    fn an_absent_flag_keeps_and_an_empty_flag_clears() {
        let kept = options_from(&flags(None, None)).expect("no flags");
        assert_eq!(kept.env_name, Change::Keep);
        assert_eq!(kept.expires_at, Change::Keep);

        let cleared = options_from(&flags(Some(""), Some(""))).expect("empty flags");
        assert_eq!(cleared.env_name, Change::Clear);
        assert_eq!(cleared.expires_at, Change::Clear);

        let set = options_from(&flags(Some("API_KEY"), Some("2030-01-02"))).expect("flags");
        assert_eq!(set.env_name, Change::Set("API_KEY".to_owned()));
    }

    #[test]
    fn an_env_name_must_be_a_safe_identifier() {
        assert_eq!(
            options_from(&flags(Some("NOT-VALID"), None))
                .expect_err("not an identifier")
                .to_string(),
            "--env-name \"NOT-VALID\" is not a valid shell identifier"
        );
        assert_eq!(
            options_from(&flags(Some("LD_PRELOAD"), None))
                .expect_err("reserved")
                .to_string(),
            "--env-name \"LD_PRELOAD\" is reserved: a shell or the dynamic loader reads it to \
             decide what code to run, so a secret cannot supply it"
        );
    }
}
