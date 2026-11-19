//! What the store hands back, and the name grammar.

use crate::timestamp::Time;

/// The lifecycle state of a secret version. A destroyed version keeps
/// its row, but its envelope is erased for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Enabled,
    Disabled,
    Destroyed,
}

impl rusqlite::types::FromSql for State {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        match Text::column_result(value)?.0.as_str() {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            "destroyed" => Ok(Self::Destroyed),
            other => Err(rusqlite::types::FromSqlError::Other(
                format!("unknown version state {}", crate::quote::quote(other)).into(),
            )),
        }
    }
}

/// A text column, read the way the Go original reads one into a string.
///
/// The vault file can be edited outside this program, so a column can
/// hold anything. Text that is not UTF-8 keeps every valid character
/// and shows U+FFFD for each bad sequence. A number reads as its
/// digits. One odd row must not stop a command that lists the others.
#[derive(Debug)]
pub(super) struct Text(pub String);

impl Text {
    pub fn into_string(self) -> String {
        self.0
    }
}

impl rusqlite::types::FromSql for Text {
    fn column_result(value: rusqlite::types::ValueRef<'_>) -> rusqlite::types::FromSqlResult<Self> {
        use rusqlite::types::{FromSqlError, ValueRef};

        match value {
            ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
                Ok(Self(String::from_utf8_lossy(bytes).into_owned()))
            }
            ValueRef::Integer(number) => Ok(Self(number.to_string())),
            ValueRef::Real(number) => Ok(Self(number.to_string())),
            ValueRef::Null => Err(FromSqlError::InvalidType),
        }
    }
}

/// Reads a text column that may be NULL.
pub(super) fn optional_text(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<String>> {
    Ok(row.get::<_, Option<Text>>(index)?.map(Text::into_string))
}

/// Reads a text column that is never NULL.
pub(super) fn text(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<String> {
    Ok(row.get::<_, Text>(index)?.into_string())
}

impl SecretMeta {
    /// Reports whether the secret is past its expiry at `now`. Expiry
    /// marks a secret stale. It never blocks resolution.
    pub fn expired(&self, now: Time) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

impl State {
    /// The text the vault column and result output carry.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
            Self::Destroyed => "destroyed",
        }
    }
}

/// A secret row without any envelope material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMeta {
    pub name: String,
    pub env_name: Option<String>,
    pub created_at: Time,
    pub updated_at: Time,
    pub deleted_at: Option<Time>,
    pub expires_at: Option<Time>,
}

/// A version row without its envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMeta {
    pub number: i64,
    pub state: State,
    pub created_at: Time,
}

/// One secret selected for a batch decrypt: its newest enabled version
/// and the columns a read checks against the envelope.
///
/// `env_name` keeps a NULL column apart from a present empty one. The
/// store never writes the second, so a read treats it as tampering.
#[derive(Debug)]
pub struct Entry {
    pub name: String,
    pub env_name: Option<String>,
    pub version: i64,
    pub expires_at: Option<Time>,
    pub envelope: Vec<u8>,
}

impl Entry {
    /// Whether the entry is past its expiry at `now`. Expiry marks a
    /// secret stale. It never blocks a read.
    pub fn expired(&self, now: Time) -> bool {
        self.expires_at.is_some_and(|expires_at| now >= expires_at)
    }
}

/// Which secrets a batch selects. The default selects every live
/// secret with an enabled version.
#[derive(Debug, Default, Clone, Copy)]
pub struct EntryFilter<'a> {
    /// Keeps only names that are the prefix or sit under it. Empty
    /// keeps all.
    pub prefix: &'a str,
    /// Keeps only secrets that carry an env name.
    pub env_named: bool,
}

/// The newest enabled version of a secret, with its sealed envelope.
#[derive(Debug)]
pub struct Resolved {
    pub secret: SecretMeta,
    pub version: VersionMeta,
    pub envelope: Vec<u8>,
}

/// One row of list and stale output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    pub secret: SecretMeta,
    /// The newest version number, or 0 when the secret has no version.
    pub latest_version: i64,
}

/// What a set changes besides the value.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SetOptions {
    pub env_name: Change<String>,
    pub expires_at: Change<Time>,
    /// Disable every older enabled version.
    pub revoke_previous: bool,
}

/// One optional attribute of a set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Change<T> {
    /// Leave whatever the secret already stores.
    #[default]
    Keep,
    /// Remove the attribute.
    Clear,
    /// Store this value.
    Set(T),
}

/// What a set did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendResult {
    pub secret: SecretMeta,
    pub version: VersionMeta,
    /// How many older versions were disabled.
    pub revoked: i64,
}

/// What a sealer is given: the recipient to seal to, the address that
/// binds the envelope to its row, and the metadata to seal in with the
/// value.
///
/// The recipient is supplied, never looked up by the caller, and it is
/// read inside the writing transaction. A caller that read it earlier
/// could seal to a recipient a concurrent rekey had already retired.
#[derive(Debug, Clone, Copy)]
pub struct SealRequest<'a> {
    pub recipient: &'a str,
    pub address: &'a str,
    pub env_name: Option<&'a str>,
    pub expires_at: Option<&'a str>,
}

/// The address baked into every envelope. It binds ciphertext to its
/// exact row.
pub fn canonical_address(name: &str, number: i64) -> String {
    format!("api/v1/{name}/{number}")
}

/// A secret name read from the vault, made safe to put in a message.
///
/// A name the grammar allows prints as it is. Any other name was put
/// there by an edit outside this program, and it can hold a newline or
/// a terminal escape sequence. It prints quoted and escaped, so it
/// cannot forge a log line or drive the terminal.
pub(super) fn shown_name(name: &str) -> std::borrow::Cow<'_, str> {
    if is_valid_name(name) {
        name.into()
    } else {
        crate::quote::quote(name).into()
    }
}

/// Reports whether `name` fits the hierarchical name grammar: segments
/// of letters, digits, dots, underscores, and dashes, each starting
/// with a letter or digit, joined by single slashes.
pub fn is_valid_name(name: &str) -> bool {
    name.split('/').all(|segment| {
        let mut bytes = segment.bytes();

        bytes
            .next()
            .is_some_and(|first| first.is_ascii_alphanumeric())
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    })
}

#[cfg(test)]
mod tests {
    use super::{Entry, canonical_address, is_valid_name, shown_name};

    #[test]
    fn a_name_from_the_vault_is_shown_safely() {
        assert_eq!(shown_name("api/one"), "api/one");
        assert_eq!(
            shown_name("api/a\nINFO fake forged\u{1b}[2K"),
            "\"api/a\\nINFO fake forged\\x1b[2K\""
        );
        assert_eq!(shown_name(""), "\"\"");
    }
    use crate::timestamp::Time;

    // A batch entry is expired from the instant of its expiry on, the
    // same boundary the metadata verbs use.
    #[test]
    fn an_entry_expires_at_its_expiry_instant() {
        let at = |text: &str| Time::parse_rfc3339(text).expect("parse");
        let entry = Entry {
            name: "api/one".to_owned(),
            env_name: None,
            version: 1,
            expires_at: Some(at("2031-01-01T00:00:00Z")),
            envelope: Vec::new(),
        };

        assert!(!entry.expired(at("2030-12-31T23:59:59Z")));
        assert!(entry.expired(at("2031-01-01T00:00:00Z")));
        assert!(entry.expired(at("2031-01-01T00:00:01Z")));
    }

    #[test]
    fn the_name_grammar() {
        for name in [
            "a",
            "api",
            "api/one",
            "a/b/c/d",
            "A.b_c-d/0",
            "9lives",
            "a.b",
            "a-",
            "a_/b.",
        ] {
            assert!(is_valid_name(name), "{name:?} must be valid");
        }

        for name in [
            "",
            "/",
            "/a",
            "a/",
            "a//b",
            ".a",
            "-a",
            "_a",
            "a/.b",
            "a b",
            "a\n",
            "a\tb",
            "caf\u{e9}",
            "a:b",
            "a\\b",
            "a/../b",
        ] {
            assert!(!is_valid_name(name), "{name:?} must be invalid");
        }
    }

    #[test]
    fn a_text_column_reads_whatever_the_file_holds() {
        let connection = rusqlite::Connection::open_in_memory().expect("open");
        let read = |sql: &str| -> rusqlite::Result<Option<String>> {
            connection.query_row(sql, [], |row| super::optional_text(row, 0))
        };

        assert_eq!(
            read("SELECT 'api/one'").expect("text").as_deref(),
            Some("api/one")
        );
        assert_eq!(
            read("SELECT CAST(x'6170692fff62' AS TEXT)")
                .expect("bad text")
                .as_deref(),
            Some("api/\u{fffd}b")
        );
        assert_eq!(
            read("SELECT x'6170692f62'").expect("blob").as_deref(),
            Some("api/b")
        );
        assert_eq!(read("SELECT 42").expect("integer").as_deref(), Some("42"));
        assert_eq!(read("SELECT NULL").expect("null"), None);

        let required = connection.query_row("SELECT NULL", [], |row| super::text(row, 0));

        assert!(required.is_err(), "a required column refuses NULL");
    }

    #[test]
    fn the_address_binds_name_and_version() {
        assert_eq!(canonical_address("api/one", 3), "api/v1/api/one/3");
    }
}
