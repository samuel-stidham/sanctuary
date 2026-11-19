//! Log records on stderr. Ports the cases of
//! `internal/logging/logging_test.go` that a real invocation can reach.
//!
//! The sensitive-key backstop and the LogValuer resolution guard call
//! sites that do not exist, so no invocation can reach them. Those stay
//! unit tests of the port's own logging module. See `tests/PARITY.md`.

use serde_json::Value;

use crate::support::{Fixture, VALUE_ONE, arg, pty, run};

fn stale_fixture() -> Fixture {
    let fixture = Fixture::new();

    fixture.set("stale/probe", VALUE_ONE, &["--expires", "2020-01-02"]);

    fixture
}

// Go: TestTextFormatByDefault
//
// The text shape: level tag first, no timestamp, logfmt-style
// attributes, and no styling bytes when stderr is not a terminal.
#[test]
fn text_format_by_default() {
    let fixture = stale_fixture();

    let got = fixture.ok("", &["get", "stale/probe"]);

    assert_eq!(
        got.stderr,
        "WARN secret expired name=stale/probe expires_at=2020-01-02T00:00:00Z\n"
    );
}

// A value that holds spaces or quotes is quoted logfmt-style, so a
// record stays one parseable line.
#[test]
fn text_format_quotes_values_that_need_it() {
    let fixture = Fixture::new();

    fixture.ok(
        b"abc\x00def\n",
        &["set", "lab/nul", "--env-name", "FAKE_NUL"],
    );
    fixture.set("lab/unnamed", VALUE_ONE, &[]);

    let ran = fixture.ok("", &["exec", "--", "true"]);

    assert_eq!(
        ran.stderr,
        "WARN secret skipped name=lab/nul reason=\"value contains a NUL byte, which an environment variable cannot hold\"\n"
    );

    let revealed = fixture.ok("", &["reveal", "--prefix", "lab/unnamed", "--format", "sh"]);

    assert_eq!(
        revealed.stderr,
        "WARN secret skipped name=lab/unnamed reason=\"has no env name\"\n"
    );
}

// Go: TestJSONFormat
//
// --log-json keeps the stdlib JSON record: time, level, msg, then the
// attributes in call order.
#[test]
fn json_format() {
    let fixture = stale_fixture();

    let got = fixture.ok("", &["--log-json", "get", "stale/probe"]);

    let line = got
        .stderr
        .strip_suffix('\n')
        .expect("one record ends with a newline");
    let record: Value = serde_json::from_str(line).expect("the record is JSON");

    assert_eq!(record["level"], "WARN");
    assert_eq!(record["msg"], "secret expired");
    assert_eq!(record["name"], "stale/probe");
    assert_eq!(record["expires_at"], "2020-01-02T00:00:00Z");

    let keys: Vec<&str> = record
        .as_object()
        .expect("a JSON object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys, ["time", "level", "msg", "name", "expires_at"]);

    assert!(line.starts_with("{\"time\":\""), "compact JSON, time first");
    assert!(line.ends_with(
        "\",\"level\":\"WARN\",\"msg\":\"secret expired\",\"name\":\"stale/probe\",\"expires_at\":\"2020-01-02T00:00:00Z\"}"
    ));

    // The timestamp is RFC3339 with a numeric offset or Z.
    let time = record["time"].as_str().expect("time is a string");
    assert!(
        time.len() >= 20 && time.as_bytes()[10] == b'T',
        "unexpected time {time:?}"
    );
}

// The record's offset follows `TZ`, and a zone that cannot be read
// prints as UTC. A hostile `TZ` or `TZDIR` must cost nothing: the run
// still ends at once, with a well-formed record.
#[test]
fn json_time_follows_tz_and_survives_a_hostile_one() {
    use std::time::{Duration, Instant};

    let fixture = stale_fixture();

    let time_under = |name: &str, value: &str| {
        let mut command = fixture.command(&["--log-json", "get", "stale/probe"]);

        command.env(name, value);

        let started = Instant::now();
        let got = run(command, "").assert_ok();

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "{name}={value} stalled the run"
        );

        let record: Value =
            serde_json::from_str(got.stderr.trim_end()).expect("the record is JSON");

        record["time"]
            .as_str()
            .expect("time is a string")
            .to_owned()
    };

    assert!(time_under("TZ", "Asia/Tokyo").ends_with("+09:00"));
    assert!(time_under("TZ", "UTC").ends_with('Z'));
    assert!(time_under("TZ", "fake/Nowhere").ends_with('Z'));
    assert!(time_under("TZ", "/dev/zero").ends_with('Z'));

    let walked = time_under("TZDIR", "/");

    assert_eq!(walked.as_bytes()[10], b'T', "{walked}");
}

// Go: TestLevelFiltering
//
// Info is the default level. --verbose lowers it to Debug. Both
// handlers share the rule.
#[test]
fn level_filtering() {
    let fixture = stale_fixture();
    let vault = arg(&fixture.vault);

    // Debug is suppressed by default, on both handlers.
    let quiet = fixture.ok("", &["list"]);
    assert!(
        quiet.stderr.is_empty(),
        "debug records must stay behind --verbose: {}",
        quiet.stderr
    );

    let quiet_json = fixture.ok("", &["--log-json", "list"]);
    assert!(quiet_json.stderr.is_empty());

    // Debug is logged when verbose, long and short spelling alike.
    for flag in ["--verbose", "-v"] {
        let verbose = fixture.ok("", &[flag, "list"]);
        assert_eq!(
            verbose.stderr,
            format!("DEBU vault opened vault_path={vault}\n")
        );
    }

    let verbose_json = fixture.ok("", &["--verbose", "--log-json", "list"]);
    let record: Value =
        serde_json::from_str(verbose_json.stderr.trim_end()).expect("the record is JSON");

    assert_eq!(record["level"], "DEBUG");
    assert_eq!(record["msg"], "vault opened");
    assert_eq!(record["vault_path"], vault);

    // Warn and error are logged at the default level.
    let warned = fixture.ok("", &["get", "stale/probe"]);
    assert!(warned.stderr.starts_with("WARN "));

    let failed = fixture.fail("", &["get", "missing/secret"]);
    assert_eq!(
        failed.stderr,
        "ERRO secret missing/secret: secret not found\n"
    );

    let failed_json = fixture.fail("", &["--log-json", "get", "missing/secret"]);
    let record: Value =
        serde_json::from_str(failed_json.stderr.trim_end()).expect("the record is JSON");

    assert_eq!(record["level"], "ERROR");
    assert_eq!(record["msg"], "secret missing/secret: secret not found");
}

// Go: TestLevelFiltering ("info logged by default")
//
// init reports through an info record and a warn record, in that order.
#[test]
fn info_records_are_logged_by_default() {
    let fixture = Fixture::empty();

    let initialized = fixture.ok("", &["init"]);
    let identity = arg(&fixture.identity);
    let vault = arg(&fixture.vault);
    let recipient = fixture.recipient();

    assert_eq!(
        initialized.stderr,
        format!(
            "INFO safetybox initialized identity_path={identity} vault_path={vault} recipient={recipient}\n\
             WARN back up the identity file now: without it every secret in this vault is \
             unrecoverable, and the passphrase alone cannot recover them, copy the identity file \
             somewhere safe and offline identity_path={identity}\n"
        )
    );
}

// Go: TestSensitiveKeyBackstopLeavesOperationalKeys
//
// The redaction backstop compares whole trailing segments, never
// substrings, so operational keys such as identity_path and vault_path
// keep rendering on both handlers.
#[test]
fn operational_keys_keep_rendering() {
    for log_json in [false, true] {
        let fixture = Fixture::empty();

        let mut args = vec![];
        if log_json {
            args.push("--log-json");
        }
        args.extend(["--verbose", "init"]);

        let initialized = fixture.ok("", &args);

        assert!(
            initialized.stderr.contains(arg(&fixture.identity)),
            "identity_path must render"
        );
        assert!(
            initialized.stderr.contains(arg(&fixture.vault)),
            "vault_path must render"
        );
        assert!(
            initialized.stderr.contains(&fixture.recipient()),
            "recipient must render"
        );
        assert!(
            !initialized.stderr.contains("[REDACTED]"),
            "no operational key may be redacted: {}",
            initialized.stderr
        );
    }
}

// Styling follows the destination. Forced color styles the level tag
// and the attribute keys of a record that is not going to a terminal,
// at the 16-color ANSI profile: a bold bright level tag, then faint
// keys and separators around plain values.
#[test]
fn forced_color_styles_records() {
    let fixture = stale_fixture();
    let forced = |args: &[&str]| {
        let mut command = fixture.command(args);
        command.env("CLICOLOR_FORCE", "1");

        run(command, "")
    };

    let got = forced(&["get", "stale/probe"]).assert_ok();

    assert_eq!(
        got.stderr,
        "\x1b[1;93mWARN\x1b[0m secret expired \x1b[2mname\x1b[0m\x1b[2m=\x1b[0mstale/probe \
         \x1b[2mexpires_at\x1b[0m\x1b[2m=\x1b[0m2020-01-02T00:00:00Z\n"
    );
    assert!(
        !got.stdout.contains('\x1b'),
        "JSON output on stdout is never styled"
    );

    let failed = forced(&["get", "missing/secret"]).assert_fails();
    assert_eq!(
        failed.stderr,
        "\x1b[1;91mERRO\x1b[0m secret missing/secret: secret not found\n"
    );

    let informed = forced(&["migrate"]).assert_ok();
    assert!(
        informed
            .stderr
            .starts_with("\x1b[1;96mINFO\x1b[0m vault is already at the current format")
    );

    let debugged = forced(&["--verbose", "list"]).assert_ok();
    assert!(
        debugged
            .stderr
            .starts_with("\x1b[1;94mDEBU\x1b[0m vault opened \x1b[2mvault_path\x1b[0m")
    );

    // JSON logs are a machine format and never carry styling.
    let json = forced(&["--log-json", "get", "stale/probe"]).assert_ok();
    assert!(!json.stderr.contains('\x1b'));
}

// Records are styled on a terminal and plain in a pipe. On a terminal
// the level tags take the 256-color palette.
#[test]
fn records_are_styled_on_a_terminal() {
    let fixture = stale_fixture();

    let mut command = fixture.command(&["--verbose", "get", "stale/probe", "--json"]);
    command.env("COLORTERM", "truecolor").env("TERM", "dumb");

    let (displayed, status) = pty::capture_on_terminal(command);

    assert!(status.success());
    assert!(displayed.contains("\x1b[1;38;5;63mDEBU\x1b[0m vault opened \x1b[2mvault_path\x1b[0m"));
    assert!(displayed.contains(
        "\x1b[1;38;5;192mWARN\x1b[0m secret expired \x1b[2mname\x1b[0m\x1b[2m=\x1b[0mstale/probe"
    ));

    // The JSON result shares the terminal and is never styled.
    let result = displayed
        .lines()
        .last()
        .expect("the JSON result is the last line");
    assert!(result.starts_with("{\"name\":\"stale/probe\""));
    assert!(!result.contains('\x1b'));

    let mut command = fixture.command(&["get", "missing/secret"]);
    command.env("COLORTERM", "truecolor").env("TERM", "dumb");

    let (displayed, status) = pty::capture_on_terminal(command);

    assert_eq!(status.code(), Some(1));
    assert_eq!(
        displayed,
        "\x1b[1;38;5;204mERRO\x1b[0m secret missing/secret: secret not found\n"
    );
}
