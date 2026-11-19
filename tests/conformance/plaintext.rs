//! Plaintext handling. Ports the observable cases of
//! `internal/secret/secret_test.go`.
//!
//! The Go tests exercise `secret.Value` and the wiping reader in
//! process: every fmt verb, zeroing on Destroy, zeroing of outgrown
//! buffers. Memory contents are not observable from outside, so those
//! stay unit tests of the port's own secret module. What is observable
//! is the outcome: values of every size round-trip exactly, and the
//! redaction marker is all any verb but reveal ever prints.

use std::fs::File;
use std::process::Stdio;

use crate::support::{Fixture, VALUE_ONE, collect, msg};

// Go: TestReadAllWiping, TestReadAllWipingHandlesDataWithEOF
//
// The wiping reader returns the exact input across sizes that span its
// 512-byte growth boundary, so the wiping of intermediate buffers never
// corrupts the content. Each value passes through it twice: once from
// stdin on set, once from the decrypted envelope on reveal.
#[test]
fn values_round_trip_across_buffer_growth_boundaries() {
    let fixture = Fixture::new();
    let sizes = [1, 511, 512, 513, 1536, 5000, 70_000];

    for size in sizes {
        // No trailing newline, so the stored value is exactly `size` bytes.
        fixture.ok("x".repeat(size), &["set", &format!("size/{size:05}")]);
    }

    let revealed = fixture.ok("", &["reveal", "--prefix", "size"]).json_array();

    assert_eq!(revealed.len(), sizes.len());

    for (entry, size) in revealed.iter().zip(sizes) {
        let value = entry["value"].as_str().expect("a value");

        assert_eq!(
            value.len(),
            size,
            "{} must round-trip at its exact size",
            entry["name"]
        );
        assert!(value.bytes().all(|byte| byte == b'x'));
    }
}

// Go: TestExposeReturnsPlaintext
//
// Arbitrary bytes come back exactly through the one verb that hands
// plaintext to a process: exec places the raw value in the child's
// environment with no encoding at all.
#[test]
fn exec_delivers_the_exact_bytes() {
    let fixture = Fixture::new();
    let value = "tab\there 'quote' \"double\" $dollar \\backslash ünïcödé 🔐 trailing space ";

    fixture.ok(value, &["set", "bytes/exact", "--env-name", "FAKE_EXACT"]);

    let ran = fixture.ok(
        "",
        &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_EXACT""#],
    );

    assert_eq!(ran.stdout, value);
    assert_eq!(fixture.reveal_value("bytes/exact"), value);
}

// Go: TestSecretValueNeverLeaks, TestMarshalJSONExactOutput
//
// get carries the value through the redacting type, so its JSON renders
// the marker by construction, pretty and compact alike.
#[test]
fn get_renders_the_redaction_marker() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let pretty = fixture.ok("", &["get", "api/one"]);
    assert!(pretty.stdout.ends_with("  \"value\": \"[REDACTED]\"\n}\n"));

    let compact = fixture.ok("", &["get", "api/one", "--json"]);
    assert!(compact.stdout.ends_with(",\"value\":\"[REDACTED]\"}\n"));

    for output in [&pretty, &compact] {
        assert!(!output.stdout.contains(VALUE_ONE));
        assert!(!output.stderr.contains(VALUE_ONE));
    }
}

// Go: TestSecretValueNeverLeaks
//
// A value that merely looks like the marker is still a value: get
// redacts it and reveal prints it.
#[test]
fn a_value_equal_to_the_marker_is_still_a_value() {
    let fixture = Fixture::new();

    fixture.set("api/marker", "[REDACTED]", &[]);

    assert_eq!(
        fixture.ok("", &["get", "api/marker"]).json()["value"],
        "[REDACTED]"
    );
    assert_eq!(fixture.reveal_value("api/marker"), "[REDACTED]");
}

// Values never come from arguments: set takes exactly one, the name.
// A second argument is a usage error, and nothing is stored.
#[test]
fn set_takes_no_value_argument() {
    let fixture = Fixture::new();

    let refused = fixture.fail("", &["set", "api/one", "fake-value-as-argument"]);

    assert!(refused.stderr.starts_with("ERRO "));
    assert_eq!(fixture.ok("", &["list", "--json"]).stdout, "[]\n");
}

// An argument too many is refused without being repeated. Someone who
// types a value where only a name belongs must not find it copied into
// the error line, in either log format.
#[test]
fn a_stray_argument_is_never_echoed() {
    const STRAY: &str = "fake-stray-argument-not-real";

    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let lines: [&[&str]; 8] = [
        &["set", "api/one", STRAY],
        &["get", "api/one", STRAY],
        &["show", "api/one", STRAY],
        &["purge", "api/one", STRAY],
        &["delete", "api/one", STRAY],
        &["disable", "api/one", "1", STRAY],
        &["list", "api", STRAY],
        &["set", "api/one", STRAY, "--log-json"],
    ];

    for args in lines {
        let refused = fixture.fail("", args);

        assert_eq!(refused.code(), Some(1), "{args:?}");
        assert!(refused.stdout.is_empty(), "{args:?}: {}", refused.stdout);
        assert!(
            !refused.stderr.contains(STRAY),
            "{args:?} repeated the stray argument: {}",
            refused.stderr
        );
    }

    // Nothing was stored, disabled, or deleted by a refused line.
    assert_eq!(fixture.reveal_value("api/one"), VALUE_ONE);
}

// JSON output escapes the characters JSON and HTML embedding require,
// exactly as the reference encoder does.
#[test]
fn reveal_json_escapes_like_the_reference_encoder() {
    let fixture = Fixture::new();

    fixture.ok(
        "<tag> & \"quoted\" \\ \u{2028} \x01 \t",
        &["set", "api/escape"],
    );

    let revealed = fixture.ok("", &["reveal", "api/escape", "--json"]);

    assert_eq!(
        revealed.stdout,
        "{\"name\":\"api/escape\",\"version\":1,\"expired\":false,\
         \"value\":\"\\u003ctag\\u003e \\u0026 \\\"quoted\\\" \\\\ \\u2028 \\u0001 \\t\"}\n"
    );
}

// Go: TestReadAllWipingSurfacesReadError, TestReadAllWipingReturnsNothingOnError
//
// A failed read of the value is reported, and nothing partial is
// stored. A directory on stdin fails every read.
#[test]
fn set_reports_a_failed_read_and_stores_nothing() {
    let fixture = Fixture::new();
    let directory = File::open(fixture.root()).expect("open a directory");

    let child = fixture
        .command(&["set", "api/unreadable"])
        .stdin(Stdio::from(directory))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("run set with a directory on stdin");

    let refused = collect(child)
        .assert_fails()
        .assert_stderr("read value from stdin: read: ");

    assert!(refused.stdout.is_empty());

    fixture
        .fail("", &["show", "api/unreadable"])
        .assert_stderr(msg::SECRET_NOT_FOUND);
}
