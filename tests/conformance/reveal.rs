//! The reveal verb. Ports `cmd/reveal_internal_test.go`, the reveal
//! cases of `cmd/review_fixes_internal_test.go` and
//! `cmd/hardening_internal_test.go`, and the reveal half of
//! `cmd/skip_failopen_internal_test.go`.

use std::process::Command;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::support::{Fixture, VALUE_ONE, VALUE_THREE, VALUE_TWO, msg};

/// The sh quoting the reference implementation applies: single quotes,
/// with an embedded quote closing, escaping itself, and reopening.
fn quote_sh(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

/// The fish quoting: backslash and single quote are the only characters
/// interpreted inside single quotes.
fn quote_fish(value: &str) -> String {
    format!("'{}'", value.replace('\\', r"\\").replace('\'', r"\'"))
}

/// The quoting cases, ordered by secret name so a batch reveal emits
/// them in this order.
const QUOTING_CASES: [(&str, &str, &str, &str, &str); 4] = [
    // (secret name, env name, value, sh rendering, fish rendering)
    (
        "quote/1-plain",
        "FAKE_Q1",
        "fake-value",
        "'fake-value'",
        "'fake-value'",
    ),
    (
        "quote/2-embedded-quote",
        "FAKE_Q2",
        "it's",
        r"'it'\''s'",
        r"'it\'s'",
    ),
    ("quote/3-newline", "FAKE_Q3", "a\nb", "'a\nb'", "'a\nb'"),
    ("quote/4-backslash", "FAKE_Q4", r"a\b", r"'a\b'", r"'a\\b'"),
];

fn quoting_fixture() -> Fixture {
    let fixture = Fixture::new();

    for (name, env_name, value, _, _) in QUOTING_CASES {
        fixture.set(name, value, &["--env-name", env_name]);
    }

    fixture
}

// Go: TestQuoteSh
#[test]
fn sh_format_quotes_values() {
    let fixture = quoting_fixture();

    let expected: String = QUOTING_CASES
        .iter()
        .map(|(_, env_name, _, sh, _)| format!("export {env_name}={sh}\n"))
        .collect();

    let revealed = fixture.ok("", &["reveal", "--prefix", "quote", "--format", "sh"]);
    assert_eq!(revealed.stdout, expected);
}

// Go: TestQuoteFish
#[test]
fn fish_format_quotes_values() {
    let fixture = quoting_fixture();

    let expected: String = QUOTING_CASES
        .iter()
        .map(|(_, env_name, _, _, fish)| format!("set -gx {env_name} {fish}\n"))
        .collect();

    let revealed = fixture.ok("", &["reveal", "--prefix", "quote", "--format", "fish"]);
    assert_eq!(revealed.stdout, expected);
}

// Go: TestIsShellIdentifier
//
// The identifier rule is observable where set validates --env-name. An
// empty name is not a refusal there: it clears the env name, which
// `set_clears_env_name` covers.
#[test]
fn set_accepts_only_shell_identifiers_as_env_names() {
    let fixture = Fixture::new();

    for (index, valid) in ["STRIPE_KEY", "_private2"].into_iter().enumerate() {
        let stored = fixture.set(
            &format!("ident/ok{index}"),
            VALUE_ONE,
            &["--env-name", valid],
        );
        assert_eq!(
            stored.json()["envName"],
            valid,
            "{valid} is a shell identifier"
        );
    }

    for (index, invalid) in ["2LEADING", "BAD-DASH", "SPACE D", "FOO=BAR", "ÜBER"]
        .into_iter()
        .enumerate()
    {
        let name = format!("ident/bad{index}");

        fixture
            .fail(
                format!("{VALUE_ONE}\n"),
                &["set", &name, "--env-name", invalid],
            )
            .assert_stderr(&format!(
                "--env-name {invalid:?} is not a valid shell identifier"
            ));

        // The refusal happens before anything is written.
        fixture
            .fail("", &["show", &name])
            .assert_stderr(msg::SECRET_NOT_FOUND);
    }
}

// Go: TestRevealMultipleNamesReturnsArray
#[test]
fn reveal_multiple_names_returns_array() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);
    fixture.set("api/two", VALUE_TWO, &[]);

    let outputs = fixture
        .ok("", &["reveal", "api/one", "api/two"])
        .json_array();

    assert_eq!(outputs.len(), 2);
    assert_eq!(outputs[0]["value"], VALUE_ONE);
    assert_eq!(outputs[1]["value"], VALUE_TWO);
}

// Go: TestRevealMissingNameFailsWholeBatch
#[test]
fn reveal_missing_name_fails_whole_batch() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let revealed = fixture
        .fail("", &["reveal", "api/one", "api/missing"])
        .assert_stderr("not found");
    assert!(
        revealed.stdout.is_empty(),
        "a failed batch must print nothing"
    );
}

// Go: TestRevealEnvFilterEmitsShellAssignments
#[test]
fn reveal_env_filter_emits_shell_assignments() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_KEY_ONE"]);
    fixture.set("api/two", VALUE_TWO, &["--env-name", "FAKE_KEY_TWO"]);
    fixture.set("no/env/name", VALUE_THREE, &[]);

    let sh = fixture.ok("", &["reveal", "--env", "--format", "sh"]);
    assert_eq!(
        sh.stdout,
        format!("export FAKE_KEY_ONE='{VALUE_ONE}'\nexport FAKE_KEY_TWO='{VALUE_TWO}'\n")
    );
    assert!(
        !sh.stdout.contains(VALUE_THREE),
        "--env must not select unnamed secrets"
    );

    let fish = fixture.ok("", &["reveal", "--env", "--format", "fish"]);
    assert_eq!(
        fish.stdout,
        format!("set -gx FAKE_KEY_ONE '{VALUE_ONE}'\nset -gx FAKE_KEY_TWO '{VALUE_TWO}'\n")
    );
}

// Go: TestRevealPrefixFilterScopesTheBatch
#[test]
fn reveal_prefix_filter_scopes_the_batch() {
    let fixture = Fixture::new();

    fixture.set(
        "projects/app/token",
        VALUE_ONE,
        &["--env-name", "FAKE_APP_TOKEN"],
    );
    fixture.set("global/other", VALUE_TWO, &["--env-name", "FAKE_OTHER"]);

    let scoped = fixture.ok(
        "",
        &["reveal", "--prefix", "projects/app", "--format", "sh"],
    );
    assert_eq!(
        scoped.stdout,
        format!("export FAKE_APP_TOKEN='{VALUE_ONE}'\n")
    );

    // Without an env name the secret is skipped with a warning, never
    // silently dropped.
    fixture.set("projects/app/unnamed", VALUE_THREE, &[]);

    let scoped = fixture.ok(
        "",
        &["reveal", "--prefix", "projects/app", "--format", "sh"],
    );
    assert!(!scoped.stdout.contains(VALUE_THREE));
    assert!(scoped.stderr.contains("projects/app/unnamed"));
    assert!(scoped.stderr.contains("no env name"));
}

// Go: TestRevealShellFormatQuotesHostileValues
#[test]
fn reveal_shell_format_quotes_hostile_values() {
    let fixture = Fixture::new();

    let hostile = "it's $(uname) `id` \\n";

    fixture.set("api/hostile", hostile, &["--env-name", "FAKE_HOSTILE"]);

    let sh = fixture.ok("", &["reveal", "--env", "--format", "sh"]);
    assert_eq!(
        sh.stdout,
        format!("export FAKE_HOSTILE={}\n", quote_sh(hostile))
    );

    let fish = fixture.ok("", &["reveal", "--env", "--format", "fish"]);
    assert_eq!(
        fish.stdout,
        format!("set -gx FAKE_HOSTILE {}\n", quote_fish(hostile))
    );
}

// Go: TestRevealShellRoundTripsThroughRealShell
//
// Sources the emitted assignments in an actual sh and fish and reads
// the value back, proving the quoting resists a hostile value rather
// than only matching the quoting helper against itself.
#[test]
fn reveal_shell_round_trips_through_real_shell() {
    let fixture = Fixture::new();

    let hostile = "it's $(echo pwned) `id` \"x\" \\ end";
    let read_back = "\nprintf '%s' \"$FAKE_HOSTILE\"";

    fixture.set("api/hostile", hostile, &["--env-name", "FAKE_HOSTILE"]);

    let sh = fixture.ok("", &["reveal", "--env", "--format", "sh"]);
    let sourced = Command::new("sh")
        .arg("-c")
        .arg(format!("{}{read_back}", sh.stdout))
        .output()
        .expect("run sh");

    assert!(sourced.status.success());
    assert_eq!(
        String::from_utf8_lossy(&sourced.stdout),
        hostile,
        "sh must read back the literal value"
    );

    // fish is optional on a build host, exactly as in the Go suite.
    let fish = fixture.ok("", &["reveal", "--env", "--format", "fish"]);

    match Command::new("fish")
        .arg("-c")
        .arg(format!("{}{read_back}", fish.stdout))
        .output()
    {
        Ok(sourced) => {
            assert!(sourced.status.success());
            assert_eq!(
                String::from_utf8_lossy(&sourced.stdout),
                hostile,
                "fish must read back the literal value"
            );
        }
        Err(err) => eprintln!("fish not installed, skipping the fish round trip: {err}"),
    }
}

// Go: TestRevealBatchJSONIncludesEnvName
#[test]
fn reveal_batch_json_includes_env_name() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_KEY_ONE"]);

    let outputs = fixture.ok("", &["reveal", "--env"]).json_array();

    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["envName"], "FAKE_KEY_ONE");
    assert_eq!(outputs[0]["value"], VALUE_ONE);
}

// Go: TestRevealEmptyFilterMatchIsEmptyArray
#[test]
fn reveal_empty_filter_match_is_empty_array() {
    let fixture = Fixture::new();

    let revealed = fixture.ok("", &["reveal", "--prefix", "nothing/here"]);
    assert_eq!(revealed.stdout.trim(), "[]");
}

// Go: TestRevealEmptyMatchNeverUnlocksIdentity
//
// A wrong passphrase fails any identity unlock, so success here proves
// an empty match never touches the identity at all.
#[test]
fn reveal_empty_match_never_unlocks_identity() {
    let mut fixture = Fixture::new();

    fixture.passphrase_file = fixture.passphrase_file_with("fake-wrong-passphrase");

    let revealed = fixture.ok("", &["reveal", "--prefix", "nothing/here"]);
    assert_eq!(revealed.stdout.trim(), "[]");
}

// Go: TestRevealSingleNameKeepsObjectShape
#[test]
fn reveal_single_name_keeps_object_shape() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let revealed = fixture.ok("", &["reveal", "api/one"]).json();

    assert!(
        revealed.is_object(),
        "single-name reveal must stay one JSON object"
    );
    assert_eq!(revealed["value"], VALUE_ONE);
}

// Go: TestRevealRejectsContradictorySelections
#[test]
fn reveal_rejects_contradictory_selections() {
    let fixture = Fixture::new();

    fixture
        .fail("", &["reveal", "api/one", "--env"])
        .assert_stderr("not both");
    fixture
        .fail("", &["reveal"])
        .assert_stderr("at least one name");
    fixture
        .fail("", &["reveal", "--env", "--format", "csv"])
        .assert_stderr("not json, sh, or fish");
}

// Go: TestRevealRejectsJSONFlagWithShellFormat
#[test]
fn reveal_rejects_json_flag_with_shell_format() {
    let fixture = Fixture::new();

    fixture
        .fail("", &["reveal", "--env", "--format", "sh", "--json"])
        .assert_stderr("--json applies to json output");
}

// Go: TestRevealExplicitNameWithoutEnvNameFailsShellFormat
//
// An explicitly named secret that cannot become an assignment fails the
// batch instead of emitting nothing with exit 0.
#[test]
fn reveal_explicit_name_without_env_name_fails_shell_format() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let revealed = fixture
        .fail("", &["reveal", "api/one", "--format", "sh"])
        .assert_stderr("has no env name");

    assert!(
        revealed.stdout.is_empty(),
        "nothing may be emitted when an explicit name fails the batch"
    );
}

// Go: TestRevealWarnsOnDuplicateEnvNames
#[test]
fn reveal_warns_on_duplicate_env_names() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &["--env-name", "FAKE_SHARED"]);
    fixture.set("api/two", VALUE_TWO, &["--env-name", "FAKE_SHARED"]);

    let revealed = fixture.ok("", &["reveal", "--env", "--format", "sh"]);

    assert!(revealed.stderr.contains("overrides"));
    assert!(
        revealed.stdout.contains(VALUE_TWO),
        "the later assignment still wins"
    );
}

// Go: TestRevealJSONBase64EncodesNonUTF8
//
// A value that is not valid UTF-8 is base64-encoded and marked, so a
// consumer gets the exact bytes back instead of U+FFFD substitutions.
#[test]
fn reveal_json_base64_encodes_non_utf8() {
    let fixture = Fixture::new();

    fixture.ok(b"\xff\xfe\xfa\n", &["set", "bin/blob"]);

    let revealed = fixture.ok("", &["reveal", "bin/blob"]);
    let object = revealed.json();

    assert_eq!(object["encoding"], "base64");
    assert!(revealed.stderr.contains("base64"));

    let decoded = STANDARD
        .decode(object["value"].as_str().expect("value is a string"))
        .expect("value is standard base64");

    assert_eq!(decoded, [0xff, 0xfe, 0xfa]);
}

// A plain UTF-8 value carries no encoding field at all, the other half
// of the base64 contract in docs/commands.md.
#[test]
fn reveal_json_omits_encoding_for_utf8() {
    let fixture = Fixture::new();

    fixture.set("api/one", VALUE_ONE, &[]);

    let object = fixture.ok("", &["reveal", "api/one"]).json();
    assert!(object.get("encoding").is_none());
}

// Go: TestRevealEmitsAnEraseLineForASkippedSecret
//
// A shell that sources reveal's output keeps whatever it already held
// under a name reveal omitted, so omitting the assignment is not enough.
#[test]
fn reveal_emits_an_erase_line_for_a_skipped_secret() {
    for (format, erase) in [
        ("sh", "unset FAKE_TAMPERED"),
        ("fish", "set --erase FAKE_TAMPERED"),
    ] {
        let fixture = Fixture::new();

        fixture.set(
            "api/tampered",
            "fake-real-value",
            &["--env-name", "FAKE_TAMPERED"],
        );
        fixture.set(
            "api/healthy",
            "fake-healthy-value",
            &["--env-name", "FAKE_HEALTHY"],
        );

        fixture.tamper_expires_at("api/tampered", "2099-01-01T00:00:00Z");

        let revealed = fixture.ok("", &["reveal", "--env", "--format", format]);

        assert!(
            revealed.stdout.contains(erase),
            "a skipped secret must erase its variable, not leave the shell's own value"
        );
        assert!(
            revealed.stdout.contains("FAKE_HEALTHY"),
            "an unrelated secret must still be delivered"
        );
        assert!(
            !revealed.stdout.contains("fake-real-value"),
            "the withheld value must never be emitted"
        );
        assert!(revealed.stderr.contains("erased"));

        // The erase must come after the assignments, so a name another
        // secret supplied is not removed by ordering alone.
        assert!(
            revealed.stdout.find(erase) > revealed.stdout.find("FAKE_HEALTHY"),
            "erase lines belong after the assignments"
        );
    }
}

// Go: TestRevealKeepsAnEnvNameAnotherSecretSupplies
#[test]
fn reveal_keeps_an_env_name_another_secret_supplies() {
    let fixture = Fixture::new();

    fixture.set(
        "api/aaa-good",
        "fake-good-value",
        &["--env-name", "FAKE_SHARED"],
    );
    fixture.set(
        "api/zzz-tampered",
        "fake-other-value",
        &["--env-name", "FAKE_SHARED"],
    );

    fixture.tamper_expires_at("api/zzz-tampered", "2099-01-01T00:00:00Z");

    let revealed = fixture.ok("", &["reveal", "--env", "--format", "sh"]);

    assert!(
        !revealed.stdout.contains("unset FAKE_SHARED"),
        "a name another secret still supplies must not be erased"
    );
    assert!(revealed.stdout.contains("fake-good-value"));
}

// Go: TestExplicitRevealStillFailsLoudOnTamper
//
// Naming a secret explicitly must still fail rather than quietly erase
// it.
#[test]
fn explicit_reveal_still_fails_loud_on_tamper() {
    let fixture = Fixture::new();

    fixture.set(
        "api/tampered",
        "fake-real-value",
        &["--env-name", "FAKE_TAMPERED"],
    );

    fixture.tamper_expires_at("api/tampered", "2099-01-01T00:00:00Z");

    let revealed = fixture
        .fail("", &["reveal", "api/tampered"])
        .assert_stderr(msg::METADATA_TAMPERED);

    assert!(!revealed.stdout.contains("fake-real-value"));
    assert!(!revealed.stderr.contains("fake-real-value"));
}

// A reader that stops early ends the command by SIGPIPE, silently, the
// way shell tools end. `reveal ... | head` must not report an error.
#[test]
fn a_reader_that_stops_early_ends_the_command_by_sigpipe() {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::process::Stdio;

    let fixture = Fixture::new();

    // Far more than a pipe holds, so the write is still in progress
    // when the reader goes away.
    fixture.set("api/large", &"fake-large-value ".repeat(20_000), &[]);

    let mut child = fixture
        .command(&["reveal", "api/large"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start reveal");

    let mut stdout = child.stdout.take().expect("stdout");
    let mut first = [0_u8; 16];

    stdout.read_exact(&mut first).expect("read the first bytes");
    drop(stdout);

    let mut stderr = String::new();

    child
        .stderr
        .take()
        .expect("stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");

    let status = child.wait().expect("wait");

    assert_eq!(status.signal(), Some(13), "ended by SIGPIPE: {status:?}");
    assert!(stderr.is_empty(), "no error record: {stderr}");
}
