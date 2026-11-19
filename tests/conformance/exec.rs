//! The exec verb. Ports `cmd/exec_args_internal_test.go`, the exec cases
//! of `cmd/hardening_internal_test.go`, and the exec half of
//! `cmd/skip_failopen_internal_test.go`.

use crate::support::{Fixture, SECRET_NAME, VALUE_ONE, VALUE_TWO, run};

const PRINT_FIRST_ARG: &str = r#"printf '%s' "$1""#;

// Go: TestExecDoesNotParseFlagsAfterTheCommand
//
// A flag placed after the child command used to bind to safetybox, so a
// trailing --vault redirected which vault was read and the child
// silently lost the argument. These invocations deliberately omit the
// `--` separator, because that is where the bug lived.
#[test]
fn exec_does_not_parse_flags_after_the_command() {
    let fixture = Fixture::new();

    // Had safetybox claimed the flag, it would have failed trying to
    // open a vault that does not exist.
    let ran = fixture.ok(
        "",
        &[
            "exec",
            "sh",
            "-c",
            r#"printf '%s %s' "$1" "$2""#,
            "sh",
            "--vault",
            "/nonexistent/evil.db",
        ],
    );
    assert_eq!(
        ran.stdout, "--vault /nonexistent/evil.db",
        "everything after the command name belongs to the child"
    );

    let ran = fixture.ok(
        "",
        &[
            "exec",
            "sh",
            "-c",
            PRINT_FIRST_ARG,
            "sh",
            "--identity",
            "/nonexistent/evil.age",
        ],
    );
    assert_eq!(ran.stdout, "--identity");

    let ran = fixture.ok("", &["exec", "sh", "-c", PRINT_FIRST_ARG, "sh", "--help"]);
    assert_eq!(
        ran.stdout, "--help",
        "exec must run the child, not print its own help"
    );

    let ran = fixture.ok("", &["exec", "sh", "-c", PRINT_FIRST_ARG, "sh", "-v"]);
    assert_eq!(ran.stdout, "-v");
}

// Go: TestExecStillAcceptsItsOwnFlagsBeforeTheCommand
#[test]
fn exec_still_accepts_its_own_flags_before_the_command() {
    let fixture = Fixture::new();
    let print_key = r#"printf '%s' "$FAKE_TEST_KEY""#;

    fixture.set(SECRET_NAME, "fake-value", &["--env-name", "FAKE_TEST_KEY"]);

    let with_separator = fixture.ok("", &["exec", "--", "sh", "-c", print_key]);
    assert_eq!(with_separator.stdout, "fake-value");

    let without_separator = fixture.ok("", &["exec", "sh", "-c", print_key]);
    assert_eq!(without_separator.stdout, "fake-value");
}

// exec passes stdin through to the child, per docs/commands.md.
#[test]
fn exec_passes_stdin_through() {
    let fixture = Fixture::new();

    let ran = fixture.ok("fake-piped-input", &["exec", "--", "cat"]);
    assert_eq!(ran.stdout, "fake-piped-input");
}

// exec needs a command to run. The wording is the argument parser's.
#[test]
fn exec_requires_a_command() {
    let fixture = Fixture::new();

    let refused = fixture.fail("", &["exec"]);

    assert!(refused.stderr.starts_with("ERRO "));
    assert!(refused.stdout.is_empty());
}

// A command that cannot be started is a safetybox error, not a child
// exit code.
#[test]
fn exec_reports_a_command_that_cannot_start() {
    let fixture = Fixture::new();

    fixture
        .fail("", &["exec", "--", "fake-command-that-does-not-exist"])
        .assert_stderr("run fake-command-that-does-not-exist:");
}

// Go: TestExecSkipsNulValuedSecret
//
// One env-named secret with a NUL byte must not break exec for every
// command. It is skipped with a warning that names it, and the other
// secrets still inject.
#[test]
fn exec_skips_nul_valued_secret() {
    let fixture = Fixture::new();

    fixture.ok(
        b"abc\x00def\n",
        &["set", "lab/nul", "--env-name", "FAKE_NUL"],
    );
    fixture.set("lab/ok", VALUE_ONE, &["--env-name", "FAKE_OK"]);

    let ran = fixture.ok("", &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_OK""#]);

    assert_eq!(ran.stdout, VALUE_ONE, "the usable secret must still inject");
    assert!(
        ran.stderr.contains("lab/nul"),
        "the skipped secret must be named"
    );
    assert!(ran.stderr.contains("NUL"));
}

/// Prints FAKE_NUL, or `absent` when it is unset, so a cleared variable
/// is told apart from an empty one.
const PRINT_NUL_OR_ABSENT: &str = r#"printf '%s' "${FAKE_NUL-absent}""#;

const STALE: &str = "fake-stale-value-not-real";

/// The longest value `env_name` can carry on Linux. The kernel measures
/// the name, the equals sign, the value, and the terminating NUL, and
/// allows 32 pages.
#[cfg(target_os = "linux")]
fn max_env_value_bytes(env_name: &str) -> usize {
    let asked = std::process::Command::new("getconf")
        .arg("PAGESIZE")
        .output()
        .expect("run getconf");
    let page: usize = String::from_utf8_lossy(&asked.stdout)
        .trim()
        .parse()
        .expect("a page size");

    32 * page - env_name.len() - "=".len() - 1
}

// Go: TestExecSkipsASecretTooLargeForAVariable
//
// One env-named secret too large for a variable must not break exec
// for every command. Linux refuses to start any program when a single
// variable is over 32 pages. The largest value that fits still
// injects. One more byte is skipped with a warning that names the
// secret, and the other secrets still inject.
#[cfg(target_os = "linux")]
#[test]
fn exec_skips_a_secret_too_large_for_a_variable() {
    let limit = max_env_value_bytes("FAKE_BIG");

    let fits = Fixture::new();

    fits.set("lab/big", &"f".repeat(limit), &["--env-name", "FAKE_BIG"]);

    let ran = fits.ok(
        "",
        &["exec", "--", "sh", "-c", r#"printf '%s' "${#FAKE_BIG}""#],
    );

    assert_eq!(
        ran.stdout,
        limit.to_string(),
        "the child must receive the whole value"
    );
    assert!(!ran.stderr.contains("secret skipped"), "{}", ran.stderr);

    let fixture = Fixture::new();

    fixture.set("lab/ok", VALUE_ONE, &["--env-name", "FAKE_OK"]);
    fixture.set(
        "lab/big",
        &"f".repeat(limit + 1),
        &["--env-name", "FAKE_BIG"],
    );

    // This process already holds a value under the name. The child
    // must not read it in place of the secret that was withheld.
    let mut command = fixture.command(&[
        "exec",
        "--",
        "sh",
        "-c",
        r#"printf '%s|%s' "$FAKE_OK" "${FAKE_BIG-absent}""#,
    ]);

    command.env("FAKE_BIG", STALE);

    let ran = run(command, "").assert_ok();

    assert_eq!(ran.stdout, format!("{VALUE_ONE}|absent"));
    assert!(
        ran.stderr.contains("lab/big"),
        "the skipped secret must be named"
    );
    assert!(
        ran.stderr
            .contains("value is too large for an environment variable, which holds at most"),
        "{}",
        ran.stderr
    );
    assert!(ran.stderr.contains("bytes under this name"));
    assert!(ran.stderr.contains("cleared from the environment"));

    // The value is intact for the verbs that do not use a variable.
    assert_eq!(fixture.reveal_value("lab/big").len(), limit + 1);
}

// Go: TestExecClearsAVariableWithheldForItsValue
//
// A secret withheld for its value must not leave a stale value of the
// same name in place. The child would read the value the calling shell
// held and could not tell it from the secret.
#[test]
fn a_withheld_secret_never_leaves_a_stale_variable() {
    let fixture = Fixture::new();

    fixture.ok(
        b"fake\x00nul\n",
        &["set", "api/nul", "--env-name", "FAKE_NUL"],
    );

    let mut command = fixture.command(&["exec", "--", "sh", "-c", PRINT_NUL_OR_ABSENT]);

    command.env("FAKE_NUL", STALE);

    let ran = run(command, "").assert_ok();

    assert_eq!(
        ran.stdout, "absent",
        "a withheld secret must leave its variable absent, never stale"
    );
    assert!(ran.stderr.contains("secret skipped"), "{}", ran.stderr);
    assert!(
        ran.stderr.contains(
            "variable cleared from the environment, so the child cannot read a stale value"
        ),
        "{}",
        ran.stderr
    );
}

// Go: TestExecWithheldSecretIsQuietInACleanEnvironment
//
// The clearing warns only when this process held the variable. With
// nothing to clear, the skip warning is the only record.
#[test]
fn a_withheld_secret_is_quiet_in_a_clean_environment() {
    let fixture = Fixture::new();

    fixture.ok(
        b"fake\x00nul\n",
        &["set", "api/nul", "--env-name", "FAKE_NUL"],
    );

    let mut command = fixture.command(&["exec", "--", "sh", "-c", PRINT_NUL_OR_ABSENT]);

    command.env_remove("FAKE_NUL");

    let ran = run(command, "").assert_ok();

    assert_eq!(ran.stdout, "absent");
    assert!(ran.stderr.contains("secret skipped"), "{}", ran.stderr);
    assert!(
        !ran.stderr.contains("cleared from the environment"),
        "{}",
        ran.stderr
    );
}

// Go: TestExecKeepsAWithheldEnvNameAnotherSecretSupplies
//
// Guards against clearing too much. A name another secret delivers is
// current.
#[test]
fn exec_keeps_a_withheld_env_name_another_secret_supplies() {
    let fixture = Fixture::new();

    fixture.set(
        "api/aaa-good",
        "fake-good-value",
        &["--env-name", "FAKE_NUL"],
    );
    fixture.ok(
        b"fake\x00nul\n",
        &["set", "api/zzz-nul", "--env-name", "FAKE_NUL"],
    );

    let mut command = fixture.command(&["exec", "--", "sh", "-c", PRINT_NUL_OR_ABSENT]);

    command.env("FAKE_NUL", STALE);

    let ran = run(command, "").assert_ok();

    assert_eq!(ran.stdout, "fake-good-value");
    assert!(
        !ran.stderr.contains("cleared from the environment"),
        "{}",
        ran.stderr
    );
}

// Go: TestExecKeepsAReservedVariableASkippedSecretNamed
//
// A reserved name is never cleared. A secret must not supply PATH, and
// skipping one must not take the inherited PATH away from the child.
#[test]
fn exec_keeps_a_reserved_variable_a_skipped_secret_named() {
    let fixture = Fixture::new();

    fixture.set(
        "api/tampered",
        "fake-real-value",
        &["--env-name", "FAKE_TAMPERED"],
    );

    // Editing the column without re-sealing makes this a mismatch skip.
    fixture.tamper_env_name("api/tampered", "PATH");

    let mut command =
        fixture.command(&["exec", "--", "sh", "-c", r#"printf '%s' "${PATH-absent}""#]);

    command.env("PATH", "/usr/bin:/bin");

    let ran = run(command, "").assert_ok();

    assert_eq!(
        ran.stdout, "/usr/bin:/bin",
        "the child must keep the PATH it inherited"
    );
    assert!(ran.stderr.contains("skipped"), "{}", ran.stderr);
    assert!(
        !ran.stderr.contains("cleared from the environment"),
        "{}",
        ran.stderr
    );
}

// Go: TestRevealErasesAVariableWithheldForItsValue
//
// A shell that sources the output keeps whatever it held under a name
// reveal left out, so the skip must write an erase line.
#[test]
fn reveal_erases_a_variable_withheld_for_its_value() {
    for (format, erase) in [
        ("sh", "unset FAKE_NUL\n"),
        ("fish", "set --erase FAKE_NUL\n"),
    ] {
        let fixture = Fixture::new();

        fixture.ok(
            b"fake\x00nul\n",
            &["set", "api/nul", "--env-name", "FAKE_NUL"],
        );
        fixture.set(
            "api/healthy",
            "fake-healthy-value",
            &["--env-name", "FAKE_HEALTHY"],
        );

        let revealed = fixture.ok("", &["reveal", "--env", "--format", format]);

        assert!(
            revealed.stdout.contains(erase),
            "{format}: {}",
            revealed.stdout
        );
        assert!(revealed.stdout.contains("FAKE_HEALTHY"), "{format}");
        assert!(revealed.stderr.contains("secret skipped"), "{format}");
        assert!(
            revealed.stderr.contains("erased"),
            "{format}: {}",
            revealed.stderr
        );
    }
}

// Go: TestRevealNeverErasesAReservedVariable
//
// Erasing PATH in a sourcing shell would be as harmful as setting it.
#[test]
fn reveal_never_erases_a_reserved_variable() {
    let fixture = Fixture::new();

    fixture.set(
        "api/tampered",
        "fake-real-value",
        &["--env-name", "FAKE_TAMPERED"],
    );
    fixture.tamper_env_name("api/tampered", "PATH");

    let revealed = fixture.ok("", &["reveal", "--env", "--format", "sh"]);

    assert!(!revealed.stdout.contains("PATH"), "{}", revealed.stdout);
}

// Go: TestExecExitCodeStaysQuietOnStderr
//
// A propagated child exit code must not carry an extra safetybox error
// line.
#[test]
fn exec_exit_code_stays_quiet_on_stderr() {
    let fixture = Fixture::new();

    let ran = fixture.run("", &["exec", "--", "sh", "-c", "exit 3"]);

    assert_eq!(ran.code(), Some(3));
    assert!(
        ran.stderr.is_empty(),
        "a child exit code adds no safetybox output: {}",
        ran.stderr
    );
}

// Go: TestExecSignalDeathMapsToShellCode
//
// A child killed by a signal exits 128 plus the signal number, matching
// shell convention.
#[test]
fn exec_signal_death_maps_to_shell_code() {
    let fixture = Fixture::new();

    let ran = fixture.run("", &["exec", "--", "sh", "-c", "kill -KILL $$"]);
    assert_eq!(ran.code(), Some(137), "SIGKILL death must map to 128+9");
}

// Go: TestExecClearsASkippedVariableSoNoStaleValueSurvives
//
// A batch verb skips a secret whose metadata no longer matches the
// sealed value. On its own that is not fail-safe: a variable the parent
// already held would stay visible to the child, and the child could not
// tell it from the real secret.
#[test]
fn exec_clears_a_skipped_variable_so_no_stale_value_survives() {
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

    let mut command = fixture.command(&[
        "--verbose",
        "exec",
        "--",
        "sh",
        "-c",
        r#"printf 'tampered=[%s] healthy=[%s]' "$FAKE_TAMPERED" "$FAKE_HEALTHY""#,
    ]);

    // A stale value already in the environment is what the child would
    // otherwise read instead of the secret safetybox declined to deliver.
    command.env("FAKE_TAMPERED", "stale-attacker-controlled-value");

    let ran = run(command, "").assert_ok();

    assert_eq!(
        ran.stdout, "tampered=[] healthy=[fake-healthy-value]",
        "a skipped secret must leave its variable absent, never stale"
    );
    assert!(ran.stderr.contains("skipped"));
    assert!(ran.stderr.contains("cleared from the environment"));

    // api/healthy is delivered and api/tampered is a metadata-mismatch
    // skip, so not_injected must count that skip.
    assert!(ran.stderr.contains("injected=1 not_injected=1"));
}

// Go: TestExecKeepsAnEnvNameAnotherSecretSupplies
//
// When one secret is skipped but another legitimately supplies the same
// env name, that value is current and must survive.
#[test]
fn exec_keeps_an_env_name_another_secret_supplies() {
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

    let ran = fixture.ok(
        "",
        &["exec", "--", "sh", "-c", r#"printf '%s' "$FAKE_SHARED""#],
    );

    assert_eq!(
        ran.stdout, "fake-good-value",
        "a name another secret still supplies must not be cleared"
    );
    assert!(ran.stderr.contains("skipped"));
    assert!(!ran.stderr.contains("cleared from the environment"));
}

// With no env-named secret there is nothing to decrypt, so exec runs
// the command without unlocking the identity. A wrong passphrase proves
// it, the same way the empty reveal filter is proven.
#[test]
fn exec_without_env_named_secrets_never_unlocks_identity() {
    let mut fixture = Fixture::new();

    fixture.set("api/unnamed", VALUE_TWO, &[]);
    fixture.passphrase_file = fixture.passphrase_file_with("fake-wrong-passphrase");

    let ran = fixture.ok("", &["exec", "--", "sh", "-c", "printf ran"]);
    assert_eq!(ran.stdout, "ran");
}

// SIGINT ends the wrapper with exit code 1 at once, and the wrapper
// does not wait for its child. The Go original gets this from its
// locked-memory library, which catches the signal in every verb. The
// child is not signalled by the wrapper, so it runs on.
#[test]
fn exec_exits_one_on_sigint_without_waiting_for_the_child() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    use crate::support::collect;

    let fixture = Fixture::new();
    let marker = fixture.root().join("child-pid");

    fixture.set(SECRET_NAME, VALUE_ONE, &["--env-name", "FAKE_INJECTED"]);

    // The child gives up the wrapper's output pipes, so reading them
    // ends when the wrapper does.
    let script = format!(
        "echo $$ > '{}'; exec sleep 30 >/dev/null 2>&1",
        marker.display()
    );

    let wrapper = fixture
        .command(&["exec", "--", "sh", "-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start the wrapper");

    let deadline = Instant::now() + Duration::from_secs(10);

    let child = loop {
        let written = std::fs::read_to_string(&marker).unwrap_or_default();

        if let Ok(pid) = written.trim().parse::<i32>() {
            break Pid::from_raw(pid);
        }

        assert!(Instant::now() < deadline, "exec never started its child");
        std::thread::sleep(Duration::from_millis(10));
    };

    let started = Instant::now();

    kill(
        Pid::from_raw(i32::try_from(wrapper.id()).expect("a pid")),
        Signal::SIGINT,
    )
    .expect("signal the wrapper");

    let ran = collect(wrapper);
    let child_survived = kill(child, None).is_ok();

    let _ = kill(child, Signal::SIGKILL);

    assert_eq!(ran.code(), Some(1), "SIGINT must exit 1: {}", ran.stderr);
    assert!(ran.stderr.is_empty(), "no error line: {}", ran.stderr);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the wrapper must not wait for the child"
    );
    assert!(child_survived, "the wrapper must not signal the child");
}
