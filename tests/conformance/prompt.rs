//! The no-echo prompt on a real terminal. Ports
//! `cmd/noecho_pty_internal_test.go`, `cmd/noecho_signal_internal_test.go`,
//! and the line-reader cases of `cmd/hardening_internal_test.go`.
//!
//! The Go tests call the prompt reader in process. Here the whole
//! binary runs with a pseudo-terminal on stdin, so the same properties
//! are checked from outside: echo is off while a line is read, the line
//! read back is exact, and the terminal state is restored afterward.

use nix::sys::signal::Signal;

use crate::support::pty::{self, Prompted};
use crate::support::{Fixture, PASSPHRASE, arg, load_identity, sandboxed};

/// The binary with the fixture's paths but no passphrase file, so every
/// passphrase comes from the prompt.
fn prompting(fixture: &Fixture, args: &[&str]) -> Prompted {
    let mut command = sandboxed(fixture.root());

    command
        .arg("--identity")
        .arg(&fixture.identity)
        .arg("--vault")
        .arg(&fixture.vault)
        .args(args);

    pty::spawn(command)
}

// Go: TestReadLineNoEchoOnPTY
//
// Echo is off while the line is read, the returned line is exact, and
// the terminal state is restored on return.
#[test]
fn prompt_reads_one_line_with_echo_off_and_restores_the_terminal() {
    let fixture = Fixture::new();

    fixture.set("api/one", "fake-prompted-value", &[]);

    let mut prompted = prompting(&fixture, &["reveal", "api/one"]);
    let before = prompted.initial_flags;

    // Wait until the prompt has disabled echo and is blocked on its
    // read, so the line below arrives with echo already off.
    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text(&format!("{PASSPHRASE}\n"));

    let (run, mut terminal) = prompted.finish();
    let run = run.assert_ok();

    assert_eq!(
        run.json()["value"],
        "fake-prompted-value",
        "the prompt must read the exact line"
    );
    assert_eq!(
        run.stderr, "Passphrase: \n",
        "the prompt and its newline go to stderr"
    );
    assert_eq!(
        terminal.local_flags(),
        before,
        "the terminal state must be restored on return"
    );
    assert!(
        !terminal.displayed().contains(PASSPHRASE),
        "the typed passphrase must never be echoed"
    );
}

// Go: TestReadLineWipingStopsAtNewline
//
// The prompt never consumes input past the newline: init reads the
// passphrase and its confirmation as two lines typed ahead together.
#[test]
fn init_prompts_for_a_passphrase_and_its_confirmation() {
    let fixture = Fixture::empty();

    let mut prompted = prompting(&fixture, &["init"]);

    prompted.terminal.wait_for_echo(false);
    prompted
        .terminal
        .type_text(&format!("{PASSPHRASE}\n{PASSPHRASE}\n"));

    let (run, mut terminal) = prompted.finish();
    let run = run.assert_ok();

    assert!(
        run.stderr
            .starts_with("Passphrase for the new identity: \nConfirm passphrase: \n")
    );
    assert!(
        terminal.echo_enabled(),
        "echo must be back on after the prompts"
    );
    assert!(!terminal.displayed().contains(PASSPHRASE));

    // The identity decrypts with exactly the typed line.
    load_identity(&fixture.identity, PASSPHRASE);
}

// A mismatched confirmation refuses and writes nothing.
#[test]
fn init_refuses_a_mismatched_confirmation() {
    let fixture = Fixture::empty();

    let mut prompted = prompting(&fixture, &["init"]);

    prompted.terminal.wait_for_echo(false);
    prompted
        .terminal
        .type_text(&format!("{PASSPHRASE}\nfake-other-passphrase\n"));

    let (run, _) = prompted.finish();

    run.assert_fails().assert_stderr("passphrases do not match");
    assert!(
        !fixture.identity.exists(),
        "a refused init must write nothing"
    );
}

// An empty line at a prompt is refused by name.
#[test]
fn prompt_refuses_an_empty_line() {
    let fixture = Fixture::empty();

    let mut prompted = prompting(&fixture, &["init"]);

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text("\n");

    let (run, _) = prompted.finish();

    run.assert_fails()
        .assert_stderr("passphrase must not be empty");
}

// set reads its value from a no-echo prompt on a terminal, and names
// the secret in the prompt.
#[test]
fn set_prompts_for_the_value_on_a_terminal() {
    let fixture = Fixture::new();

    let mut prompted = pty::spawn(fixture.command(&["set", "api/typed"]));

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text("fake-typed-value-not-real\n");

    let (run, mut terminal) = prompted.finish();
    let run = run.assert_ok();

    assert_eq!(run.stderr, "Value for api/typed: \n");
    assert_eq!(run.json()["version"], 1);
    assert!(!terminal.displayed().contains("fake-typed-value-not-real"));
    assert_eq!(
        fixture.reveal_value("api/typed"),
        "fake-typed-value-not-real"
    );
}

// An empty value at the prompt is refused as a value, not a passphrase.
#[test]
fn set_prompt_refuses_an_empty_value() {
    let fixture = Fixture::new();

    let mut prompted = pty::spawn(fixture.command(&["set", "api/typed"]));

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text("\n");

    let (run, _) = prompted.finish();

    run.assert_fails().assert_stderr("value must not be empty");
}

// Go: TestReadLineWipingSurvivesGrowth
//
// A line longer than the reader's initial buffer survives intact, so
// the wiping of outgrown buffers never corrupts a long entry.
#[test]
fn prompt_reads_a_line_longer_than_its_buffer() {
    let fixture = Fixture::new();
    let long = "x".repeat(700);

    let mut prompted = pty::spawn(fixture.command(&["set", "api/long"]));

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text(&format!("{long}\n"));

    let (run, _) = prompted.finish();
    run.assert_ok();

    assert_eq!(fixture.reveal_value("api/long"), long);
}

// Go: TestReadLineWipingReturnsDataAtEndOfInput
//
// Input that ends without a newline still yields the line. On a
// terminal, end of input is the EOF character: the first one flushes
// the pending line and the second reports end of input.
#[test]
fn prompt_returns_the_line_at_end_of_input() {
    let fixture = Fixture::new();

    let mut prompted = pty::spawn(fixture.command(&["set", "api/eof"]));

    prompted.terminal.wait_for_echo(false);
    prompted
        .terminal
        .type_text("fake-unterminated-value\x04\x04");

    let (run, _) = prompted.finish();
    run.assert_ok();

    assert_eq!(fixture.reveal_value("api/eof"), "fake-unterminated-value");
}

// passwd prompts for the current passphrase, then for the new one and
// its confirmation.
#[test]
fn passwd_prompts_for_current_and_new_passphrases() {
    let fixture = Fixture::new();

    let mut prompted = prompting(&fixture, &["passwd"]);

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text(&format!(
        "{PASSPHRASE}\nfake-next-passphrase\nfake-next-passphrase\n"
    ));

    let (run, _) = prompted.finish();
    let run = run.assert_ok();

    assert!(
        run.stderr
            .starts_with("Current passphrase: \nNew passphrase: \nConfirm passphrase: \n")
    );

    load_identity(&fixture.identity, "fake-next-passphrase");
}

// Go: TestPromptSignalRestoresEchoAndExits
//
// A terminating signal at a prompt must put echo back and end the
// process. Restoring alone would leave the read running with echo on,
// and the rest of the passphrase would be echoed to the terminal.
#[test]
fn prompt_signal_restores_echo_and_exits() {
    for signal in [Signal::SIGTERM, Signal::SIGHUP, Signal::SIGQUIT] {
        let fixture = Fixture::new();

        fixture.set("api/one", "fake-prompted-value", &[]);

        let prompted = prompting(&fixture, &["reveal", "api/one"]);
        let before = prompted.initial_flags;

        prompted.terminal.wait_for_echo(false);
        prompted.signal(signal);

        let (run, terminal) = prompted.finish();

        assert_eq!(
            run.code(),
            Some(1),
            "{signal} at a prompt must terminate the process with exit 1, got {:?}",
            run.status
        );
        assert!(
            run.stdout.is_empty(),
            "{signal} must end the run before any output"
        );
        assert_eq!(
            terminal.local_flags(),
            before,
            "{signal}: the terminal must be restored before the process exits"
        );
        assert!(
            terminal.echo_enabled(),
            "{signal}: echo must be back on, so a broken shell is not left behind"
        );
    }
}

// A passphrase file takes precedence over the terminal: no prompt
// appears and echo is never touched.
#[test]
fn passphrase_file_suppresses_the_prompt_on_a_terminal() {
    let fixture = Fixture::new();

    fixture.set("api/one", "fake-prompted-value", &[]);

    let prompted = pty::spawn(fixture.command(&["reveal", "api/one"]));
    let (run, terminal) = prompted.finish();
    let run = run.assert_ok();

    assert!(
        run.stderr.is_empty(),
        "no prompt may appear: {}",
        run.stderr
    );
    assert!(terminal.echo_enabled());
    assert_eq!(run.json()["value"], "fake-prompted-value");

    // The same holds for the new-passphrase flag on passwd.
    let next = fixture.passphrase_file_with("fake-next-passphrase");
    let prompted = pty::spawn(fixture.command(&["passwd", "--new-passphrase-file", arg(&next)]));
    let (run, _) = prompted.finish();

    assert!(!run.assert_ok().stderr.contains("passphrase: "));
}

// Go: TestSignalRestoreTeardownStopsTheHandler
//
// The prompt's signal handler comes down with the prompt. A signal
// that arrives later, while exec is running its child, is not swallowed
// by a stale handler: it takes its default action and ends safetybox by
// that signal, rather than with the prompt handler's exit 1.
#[test]
fn prompt_signal_handler_is_torn_down_after_the_prompt() {
    use std::os::unix::process::ExitStatusExt;
    use std::time::{Duration, Instant};

    let fixture = Fixture::new();
    let marker = fixture.root().join("child-is-running");

    fixture.set(
        "api/one",
        "fake-prompted-value",
        &["--env-name", "FAKE_PROMPTED"],
    );

    let mut prompted = prompting(
        &fixture,
        &[
            "exec",
            "--",
            "sh",
            "-c",
            &format!("touch '{}'; sleep 1", marker.display()),
        ],
    );

    prompted.terminal.wait_for_echo(false);
    prompted.terminal.type_text(&format!("{PASSPHRASE}\n"));

    // The child only starts once the prompt has returned and the
    // identity has been unlocked.
    let deadline = Instant::now() + Duration::from_secs(10);

    while !marker.exists() {
        assert!(Instant::now() < deadline, "exec never started its child");
        std::thread::sleep(Duration::from_millis(10));
    }

    prompted.signal(Signal::SIGTERM);

    let (run, terminal) = prompted.finish();

    assert_eq!(
        run.status.signal(),
        Some(Signal::SIGTERM as i32),
        "a torn-down handler must not catch the signal: {:?}",
        run.status
    );
    assert!(terminal.echo_enabled());
}
