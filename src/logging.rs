//! The process-wide structured logger.
//!
//! Diagnostics are leveled records on stderr. The text format is for
//! people: a level tag, the message, then `key=value` attributes,
//! styled on a terminal and plain in a pipe. The JSON format is for log
//! shippers and never changes shape. Both redact any attribute whose
//! key names secret-bearing content.
//!
//! Log operations, never operand values. Secret plaintext must never
//! reach a record. [`crate::secret::Value`] redacts itself, and the key
//! backstop here guards a call site that logs a raw string by mistake.

use std::fmt::{self, Write as _};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Mutex, PoisonError};

use crate::color::Profile;
use crate::json::{self, Escape};
use crate::quote::{is_printable, write_escaped};
use crate::secret::{self, REDACTED};
use crate::timestamp::Time;

/// How severe a record is. The default threshold is [`Level::Info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    /// The four-letter tag the text format opens a record with.
    fn tag(self) -> &'static str {
        match self {
            Self::Debug => "DEBU",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERRO",
        }
    }

    /// The level name the JSON format carries.
    fn name(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }

    /// The style of the level tag. A terminal with a palette gets the
    /// palette color. Anything less gets the nearest bright ANSI color.
    fn style(self, profile: Profile) -> &'static str {
        match (self, profile >= Profile::Ansi256) {
            (Self::Debug, true) => "1;38;5;63",
            (Self::Info, true) => "1;38;5;86",
            (Self::Warn, true) => "1;38;5;192",
            (Self::Error, true) => "1;38;5;204",
            (Self::Debug, false) => "1;94",
            (Self::Info, false) => "1;96",
            (Self::Warn, false) => "1;93",
            (Self::Error, false) => "1;91",
        }
    }
}

/// One attribute value. Strings and integers are all a record needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Text(String),
    Integer(i64),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text(text) => f.write_str(text),
            Self::Integer(number) => write!(f, "{number}"),
        }
    }
}

impl From<&str> for Value {
    fn from(text: &str) -> Self {
        Self::Text(text.to_owned())
    }
}

impl From<String> for Value {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<&String> for Value {
    fn from(text: &String) -> Self {
        Self::Text(text.clone())
    }
}

impl From<&Path> for Value {
    fn from(path: &Path) -> Self {
        Self::Text(path.display().to_string())
    }
}

impl From<i64> for Value {
    fn from(number: i64) -> Self {
        Self::Integer(number)
    }
}

impl From<usize> for Value {
    fn from(number: usize) -> Self {
        Self::Integer(i64::try_from(number).unwrap_or(i64::MAX))
    }
}

impl From<&secret::Value> for Value {
    /// A secret logs as the redaction marker under any key.
    fn from(value: &secret::Value) -> Self {
        Self::Text(value.to_string())
    }
}

/// One `key = value` attribute of a record.
pub type Field<'a> = (&'a str, Value);

/// How records are rendered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// For people, styled as far as `Profile` allows.
    Text(Profile),
    /// One JSON object per line, never styled.
    Json,
}

/// How the logger is built.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    /// Lowers the threshold from Info to Debug.
    pub verbose: bool,
    /// Switches the format from text to JSON.
    pub json: bool,
}

/// A logger writing to one destination.
pub struct Logger {
    threshold: Level,
    format: Format,
    out: Box<dyn Write + Send>,
}

impl Logger {
    /// Builds a logger writing to `out`. `profile` is the color the
    /// destination takes, and matters only to the text format.
    pub fn new(out: impl Write + Send + 'static, options: Options, profile: Profile) -> Self {
        Self {
            threshold: if options.verbose {
                Level::Debug
            } else {
                Level::Info
            },
            format: if options.json {
                Format::Json
            } else {
                Format::Text(profile)
            },
            out: Box::new(out),
        }
    }

    /// Writes one record, if `level` meets the threshold. A failed
    /// write is dropped: a diagnostic that cannot be written has
    /// nowhere to report that.
    pub fn log(&mut self, level: Level, message: &str, fields: &[Field<'_>]) {
        if level < self.threshold {
            return;
        }

        let record = match self.format {
            Format::Text(profile) => render_text(profile, level, message, fields),
            Format::Json => render_json(&timestamp(), level, message, fields),
        };

        let _ = self.out.write_all(record.as_bytes());
    }
}

/// The default logger. `None` until [`setup`] runs.
static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

/// Installs the process-wide logger on stderr.
pub fn setup(options: Options) {
    install(Logger::new(io::stderr(), options, Profile::stderr()));
}

/// Installs `logger` as the process-wide logger.
pub fn install(logger: Logger) {
    *LOGGER.lock().unwrap_or_else(PoisonError::into_inner) = Some(logger);
}

/// Writes one record through the process-wide logger. Before [`setup`]
/// runs there is no logger and the record is dropped.
pub fn log(level: Level, message: &str, fields: &[Field<'_>]) {
    if let Some(logger) = LOGGER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        logger.log(level, message, fields);
    }
}

/// Logs at a level with `"key" => value` attributes.
#[macro_export]
macro_rules! log_record {
    ($level:expr, $message:expr $(, $key:literal => $value:expr)* $(,)?) => {
        $crate::logging::log(
            $level,
            $message,
            &[$(($key, $crate::logging::Value::from($value))),*],
        )
    };
}

/// Logs a debug record. See [`log_record!`].
#[macro_export]
macro_rules! debug {
    ($($record:tt)*) => { $crate::log_record!($crate::logging::Level::Debug, $($record)*) };
}

/// Logs an info record. See [`log_record!`].
#[macro_export]
macro_rules! info {
    ($($record:tt)*) => { $crate::log_record!($crate::logging::Level::Info, $($record)*) };
}

/// Logs a warn record. See [`log_record!`].
#[macro_export]
macro_rules! warn {
    ($($record:tt)*) => { $crate::log_record!($crate::logging::Level::Warn, $($record)*) };
}

/// Logs an error record. See [`log_record!`].
#[macro_export]
macro_rules! error {
    ($($record:tt)*) => { $crate::log_record!($crate::logging::Level::Error, $($record)*) };
}

/// Reports whether `key` names secret-bearing content.
///
/// A key matches when a denylist word is its ASCII-case-insensitive
/// suffix and the word stands alone: as the whole key, as a segment
/// after `_`, `-`, or `.`, or as a camelCase hump such as `ApiToken`.
/// The hump rule also fires on an all-caps key such as `APIKEY`, which
/// over-redacts by design so the backstop fails closed. Substring
/// matching is deliberately absent, so operational keys such as
/// `identity_path` and `vault_path` keep rendering. Lowercase
/// concatenations such as `apikey` have no separator or hump, so the
/// common ones are denylist words in their own right.
fn is_sensitive_key(key: &str) -> bool {
    const WORDS: [&str; 18] = [
        "passphrase",
        "value",
        "plaintext",
        "identity",
        "secret",
        "password",
        "token",
        "key",
        "passwd",
        "credential",
        "credentials",
        "creds",
        "apikey",
        "authtoken",
        "secretkey",
        "privatekey",
        "privkey",
        "sshkey",
    ];

    let bytes = key.as_bytes();

    WORDS.iter().any(|word| {
        let Some(start) = bytes.len().checked_sub(word.len()) else {
            return false;
        };

        // Every word is ASCII, so a byte-length suffix that matches is
        // ASCII too and `start` is a character boundary.
        if !bytes[start..].eq_ignore_ascii_case(word.as_bytes()) {
            return false;
        }

        start == 0
            || matches!(bytes[start - 1], b'_' | b'-' | b'.')
            || bytes[start].is_ascii_uppercase()
    })
}

/// The value a record renders for `key`: the marker for a sensitive
/// key, whatever was logged under it.
fn rendered_value(key: &str, value: &Value) -> Value {
    if is_sensitive_key(key) {
        Value::Text(REDACTED.to_owned())
    } else {
        value.clone()
    }
}

/// Reports whether a text value must be quoted to stay one token.
fn needs_quoting(text: &str) -> bool {
    text.chars()
        .any(|c| c == '"' || c == '=' || c == ' ' || !is_printable(c))
}

/// Escapes what cannot render raw in a text value.
fn escape_text(text: &str, escape_quotes: bool) -> String {
    let mut escaped = String::with_capacity(text.len());

    for c in text.chars() {
        if c == '"' && escape_quotes {
            escaped.push_str("\\\"");
        } else if is_printable(c) {
            escaped.push(c);
        } else {
            write_escaped(&mut escaped, c).expect("writing to a String cannot fail");
        }
    }

    escaped
}

/// Renders one text record: level tag, message, then attributes.
fn render_text(profile: Profile, level: Level, message: &str, fields: &[Field<'_>]) -> String {
    const FAINT: &str = "2";

    let mut record = profile.paint(level.style(profile), level.tag());

    record.push(' ');
    record.push_str(message);

    let separator = profile.paint(FAINT, "=");

    for (index, (key, value)) in fields.iter().enumerate() {
        // An attribute with no key has nothing to be found by.
        if key.is_empty() {
            continue;
        }

        let text = rendered_value(key, value).to_string();
        let styled_key = profile.paint(FAINT, key);

        if text.contains('\n') {
            // A multi-line value keeps its lines, each marked as part
            // of the one attribute.
            let indent = profile.paint(FAINT, "  │ ");
            let more_fields = index + 1 < fields.len();

            write!(record, "\n  {styled_key}{separator}").expect("writing to a String cannot fail");

            let mut lines = text.split('\n').peekable();

            while let Some(line) = lines.next() {
                let last = lines.peek().is_none();

                if last && line.is_empty() {
                    break;
                }

                record.push('\n');
                record.push_str(&indent);
                record.push_str(&escape_text(line, false));

                if last && more_fields {
                    record.push('\n');
                }
            }

            continue;
        }

        record.push(' ');
        record.push_str(&styled_key);
        record.push_str(&separator);

        if text.is_empty() {
            record.push_str("\"\"");
        } else if needs_quoting(&text) {
            write!(record, "\"{}\"", escape_text(&text, true))
                .expect("writing to a String cannot fail");
        } else {
            record.push_str(&text);
        }
    }

    record.push('\n');

    record
}

/// Renders one JSON record: time, level, msg, then attributes in call
/// order.
fn render_json(time: &str, level: Level, message: &str, fields: &[Field<'_>]) -> String {
    let mut record = String::from("{\"time\":");

    json::push_string(&mut record, time, Escape::Minimal);
    record.push_str(",\"level\":");
    json::push_string(&mut record, level.name(), Escape::Minimal);
    record.push_str(",\"msg\":");
    json::push_string(&mut record, message, Escape::Minimal);

    for (key, value) in fields {
        if key.is_empty() {
            continue;
        }

        record.push(',');
        json::push_string(&mut record, key, Escape::Minimal);
        record.push(':');

        match rendered_value(key, value) {
            Value::Text(text) => json::push_string(&mut record, &text, Escape::Minimal),
            Value::Integer(number) => {
                write!(record, "{number}").expect("writing to a String cannot fail");
            }
        }
    }

    record.push_str("}\n");

    record
}

/// The current local time as RFC 3339 with up to nanosecond precision.
fn timestamp() -> String {
    Time::now_local().to_output()
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};
    use std::sync::{Arc, Mutex};

    use serde_json::Value as Json;

    use super::{Level, Logger, Options, Value, is_sensitive_key, render_json, render_text};
    use crate::color::Profile;
    use crate::secret;

    // Obviously fake test material, never a real secret.
    const FAKE_PLAINTEXT: &str = "fake-log-plaintext-not-real";

    /// A destination a test can read back.
    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Buffer {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().expect("buffer lock").clone()).expect("UTF-8 records")
        }
    }

    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().expect("buffer lock").extend_from_slice(bytes);

            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    const BOTH_FORMATS: [Options; 2] = [
        Options {
            verbose: false,
            json: false,
        },
        Options {
            verbose: false,
            json: true,
        },
    ];

    /// Logs one warn record carrying `key = value` and returns what the
    /// destination received.
    fn logged(options: Options, key: &str, value: Value) -> String {
        let buffer = Buffer::default();

        Logger::new(buffer.clone(), options, Profile::Plain).log(
            Level::Warn,
            "probe",
            &[(key, value)],
        );

        buffer.text()
    }

    // Go: TestSecretValueRedactedThroughHandler, TestCharmPathResolvesLogValuer
    //
    // A real secret under a non-sensitive key exercises the type's own
    // redaction rather than the key denylist. Both formats must redact.
    #[test]
    fn secret_value_is_redacted_through_the_logger() {
        let value = secret::Value::new(FAKE_PLAINTEXT.as_bytes());

        for options in BOTH_FORMATS {
            let record = logged(options, "payload", Value::from(&value));

            assert!(record.contains("[REDACTED]"));
            assert!(
                !record.contains(FAKE_PLAINTEXT),
                "the secret must be redacted: {record}"
            );
        }
    }

    // Go: TestSetupInstallsDefault
    //
    // The process-wide logger is the one the macros write through. No
    // other test in this crate installs one, so this cannot race.
    #[test]
    fn install_sets_the_process_wide_logger() {
        let buffer = Buffer::default();

        super::install(Logger::new(
            buffer.clone(),
            Options::default(),
            Profile::Plain,
        ));

        crate::warn!("probe message", "verb" => "list", "count" => 2_usize);
        crate::debug!("dropped below the threshold");

        assert_eq!(buffer.text(), "WARN probe message verb=list count=2\n");
    }

    // Go: TestSensitiveKeyBackstopRedactsRawString
    //
    // A raw string logged under a sensitive key is redacted even though
    // a plain string cannot redact itself. Case variants and compound
    // keys pin the suffix-segment matcher.
    #[test]
    fn sensitive_key_backstop_redacts_a_raw_string() {
        let keys = [
            "passphrase",
            "value",
            "plaintext",
            "identity",
            "secret",
            "password",
            "token",
            "key",
            "Password",
            "PASSWORD",
            "Token",
            "TOKEN",
            "api_token",
            "API_TOKEN",
            "API-Token",
            "ApiToken",
            "client_secret",
            "DB-Password",
            "db.password",
            "api_key",
            "passwd",
            "Passwd",
            "PASSWD",
            "db_passwd",
            "DbPasswd",
            "apikey",
            "Apikey",
            "x-apikey",
            "authtoken",
            "secretkey",
            "privatekey",
            "privkey",
            "sshkey",
            "credential",
            "credentials",
            "creds",
            "aws_credentials",
            "AwsCreds",
        ];

        for key in keys {
            for options in BOTH_FORMATS {
                let record = logged(options, key, Value::from(FAKE_PLAINTEXT));

                assert!(
                    record.contains("[REDACTED]"),
                    "key {key:?} must be redacted"
                );
                assert!(
                    !record.contains(FAKE_PLAINTEXT),
                    "raw string under {key:?} must not leak"
                );
            }
        }
    }

    // Go: TestSensitiveKeyBackstopLeavesOperationalKeys
    //
    // Every attribute key the crate logs. None may redact: the matcher
    // compares whole trailing segments, never substrings. `monkey` and
    // `sacred` pin the boundary rules against careless denylist growth.
    #[test]
    fn sensitive_key_backstop_leaves_operational_keys() {
        let keys = [
            "identity_path",
            "vault_path",
            "lock_path",
            "name",
            "env_name",
            "recipient",
            "expires_at",
            "stored_as",
            "count",
            "reason",
            "previous",
            "mode",
            "chmod",
            "label",
            "loose_path",
            "error",
            "version",
            "entries",
            "skipped",
            "injected",
            "not_injected",
            "monkey",
            "sacred",
        ];

        for key in keys {
            for options in BOTH_FORMATS {
                let record = logged(options, key, Value::from("operational-detail"));

                assert!(
                    record.contains("operational-detail"),
                    "key {key:?} must keep rendering"
                );
                assert!(
                    !record.contains("[REDACTED]"),
                    "key {key:?} must not be redacted"
                );
            }
        }
    }

    // A multi-byte key can never align with an ASCII word, and a key
    // shorter than every word matches nothing.
    #[test]
    fn sensitive_key_matcher_handles_odd_keys() {
        assert!(!is_sensitive_key(""));
        assert!(!is_sensitive_key("ke"));
        assert!(!is_sensitive_key("clé"));
        assert!(is_sensitive_key("clé_key"));
        assert!(is_sensitive_key("APIKEY"));
    }

    // Go: TestLevelFiltering
    #[test]
    fn level_filtering() {
        let quiet = Options::default();
        let verbose = Options {
            verbose: true,
            json: false,
        };
        let quiet_json = Options {
            verbose: false,
            json: true,
        };

        let cases = [
            ("debug suppressed by default", quiet, Level::Debug, false),
            ("info logged by default", quiet, Level::Info, true),
            ("warn logged by default", quiet, Level::Warn, true),
            ("error logged by default", quiet, Level::Error, true),
            ("debug logged when verbose", verbose, Level::Debug, true),
            (
                "debug suppressed by default json",
                quiet_json,
                Level::Debug,
                false,
            ),
            ("info logged by default json", quiet_json, Level::Info, true),
        ];

        for (name, options, level, want_logged) in cases {
            let buffer = Buffer::default();

            Logger::new(buffer.clone(), options, Profile::Plain).log(level, "probe message", &[]);

            if want_logged {
                assert!(buffer.text().contains("probe message"), "{name}");
            } else {
                assert!(buffer.text().is_empty(), "{name}");
            }
        }
    }

    // Go: TestTextFormatByDefault
    //
    // Level tag first, no timestamp, logfmt-style attributes.
    #[test]
    fn text_format() {
        assert_eq!(
            logged(Options::default(), "verb", Value::from("list")),
            "WARN probe verb=list\n"
        );
        assert_eq!(
            render_text(
                Profile::Plain,
                Level::Debug,
                "newest enabled version resolved",
                &[
                    ("name", Value::from("api/one")),
                    ("version", Value::from(1_i64))
                ],
            ),
            "DEBU newest enabled version resolved name=api/one version=1\n"
        );
    }

    // A value that would not read as one token is quoted and escaped.
    #[test]
    fn text_format_quotes_values_that_need_it() {
        let render = |value: &str| {
            render_text(
                Profile::Plain,
                Level::Warn,
                "probe",
                &[("reason", Value::from(value))],
            )
        };

        assert_eq!(
            render("has no env name"),
            "WARN probe reason=\"has no env name\"\n"
        );
        assert_eq!(render("a=b"), "WARN probe reason=\"a=b\"\n");
        assert_eq!(
            render("say \"hi\""),
            "WARN probe reason=\"say \\\"hi\\\"\"\n"
        );
        assert_eq!(render("tab\there"), "WARN probe reason=\"tab\\there\"\n");
        assert_eq!(render(""), "WARN probe reason=\"\"\n");
        assert_eq!(render("/plain/path"), "WARN probe reason=/plain/path\n");
    }

    // A multi-line value keeps its lines, marked as one attribute, so
    // an injected newline cannot pose as a record of its own.
    #[test]
    fn text_format_marks_a_multi_line_value() {
        assert_eq!(
            render_text(
                Profile::Plain,
                Level::Warn,
                "probe",
                &[
                    ("error", Value::from("line one\nWARN fake")),
                    ("name", Value::from("x"))
                ],
            ),
            "WARN probe\n  error=\n  │ line one\n  │ WARN fake\n name=x\n"
        );
    }

    // Go: TestCharmPathInlinesEmptyKeyGroup
    //
    // The Go logger takes grouped attributes, and an empty-key group
    // must inline its members rather than vanish. This logger has flat
    // attributes only, so the one empty-key shape left is an attribute
    // with no key, which is dropped without taking its neighbors along.
    #[test]
    fn an_attribute_without_a_key_is_dropped_alone() {
        let fields = [
            ("", Value::from(FAKE_PLAINTEXT)),
            ("token", Value::from(FAKE_PLAINTEXT)),
        ];

        let text = render_text(Profile::Plain, Level::Warn, "probe", &fields);
        let json = render_json("t", Level::Warn, "probe", &fields);

        assert_eq!(text, "WARN probe token=[REDACTED]\n");
        assert_eq!(
            json,
            "{\"time\":\"t\",\"level\":\"WARN\",\"msg\":\"probe\",\"token\":\"[REDACTED]\"}\n"
        );
    }

    // The level tag and the keys are styled, the message and the values
    // never are. A palette terminal gets palette colors.
    #[test]
    fn text_format_styles_follow_the_profile() {
        let fields = [("name", Value::from("stale/probe"))];

        assert_eq!(
            render_text(Profile::Ansi, Level::Warn, "secret expired", &fields),
            "\x1b[1;93mWARN\x1b[0m secret expired \x1b[2mname\x1b[0m\x1b[2m=\x1b[0mstale/probe\n"
        );

        for (level, ansi, palette) in [
            (
                Level::Debug,
                "\x1b[1;94mDEBU\x1b[0m",
                "\x1b[1;38;5;63mDEBU\x1b[0m",
            ),
            (
                Level::Info,
                "\x1b[1;96mINFO\x1b[0m",
                "\x1b[1;38;5;86mINFO\x1b[0m",
            ),
            (
                Level::Warn,
                "\x1b[1;93mWARN\x1b[0m",
                "\x1b[1;38;5;192mWARN\x1b[0m",
            ),
            (
                Level::Error,
                "\x1b[1;91mERRO\x1b[0m",
                "\x1b[1;38;5;204mERRO\x1b[0m",
            ),
        ] {
            assert_eq!(
                render_text(Profile::Ansi, level, "m", &[]),
                format!("{ansi} m\n")
            );
            assert_eq!(
                render_text(Profile::Ansi256, level, "m", &[]),
                format!("{palette} m\n")
            );
            assert_eq!(
                render_text(Profile::TrueColor, level, "m", &[]),
                format!("{palette} m\n")
            );
        }
    }

    // Go: TestJSONFormat
    #[test]
    fn json_format() {
        let record = logged(
            Options {
                verbose: false,
                json: true,
            },
            "verb",
            Value::from("list"),
        );
        let parsed: Json = serde_json::from_str(&record).expect("the record is JSON");

        assert_eq!(parsed["level"], "WARN");
        assert_eq!(parsed["msg"], "probe");
        assert_eq!(parsed["verb"], "list");
        assert!(
            parsed["time"]
                .as_str()
                .is_some_and(|time| time.as_bytes()[10] == b'T')
        );
        assert!(record.ends_with("}\n"));

        assert_eq!(
            render_json(
                "2026-11-17T13:08:53.654830289-05:00",
                Level::Debug,
                "newest enabled version resolved",
                &[
                    ("name", Value::from("api/one")),
                    ("version", Value::from(1_i64))
                ],
            ),
            "{\"time\":\"2026-11-17T13:08:53.654830289-05:00\",\"level\":\"DEBUG\",\
             \"msg\":\"newest enabled version resolved\",\"name\":\"api/one\",\"version\":1}\n"
        );
    }

    // JSON records are a machine format and never carry styling, and a
    // newline in a message stays inside its string.
    #[test]
    fn json_format_escapes_and_is_never_styled() {
        let record = render_json("t", Level::Error, "line one\nline two", &[]);

        assert_eq!(record.lines().count(), 1);
        assert!(record.contains("line one\\nline two"));
        assert!(!record.contains('\x1b'));
    }
}
