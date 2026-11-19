//! A pseudo-terminal for driving the no-echo prompt.
//!
//! Pipes cover the reading loop, but only a terminal exercises the
//! termios handling: echo off while the line is read, and the terminal
//! put back afterward.

use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::openpty;
use nix::sys::signal::{Signal, kill};
use nix::sys::termios::{LocalFlags, tcgetattr};
use nix::unistd::Pid;

use super::{RUN_DEADLINE, Run, collect};

/// How long a prompt may take to reach the state a test waits for.
const PROMPT_DEADLINE: Duration = Duration::from_secs(10);

/// Both ends of a pseudo-terminal. The test keeps the slave open too,
/// so it can read the terminal state while the child owns stdin.
pub struct Terminal {
    master: File,
    slave: OwnedFd,
}

impl Terminal {
    pub fn open() -> Self {
        let pair = openpty(None, None).expect("open a pseudo-terminal");

        Self {
            master: File::from(pair.master),
            slave: pair.slave,
        }
    }

    /// The terminal's local mode flags, which carry the echo bit.
    pub fn local_flags(&self) -> LocalFlags {
        tcgetattr(self.slave.as_fd())
            .expect("read terminal state")
            .local_flags
    }

    pub fn echo_enabled(&self) -> bool {
        self.local_flags().contains(LocalFlags::ECHO)
    }

    /// Polls until echo reaches `enabled`. A fixed sleep would be flaky
    /// under load, and typing before echo is off would leak the line.
    #[track_caller]
    pub fn wait_for_echo(&self, enabled: bool) {
        let deadline = Instant::now() + PROMPT_DEADLINE;

        while self.echo_enabled() != enabled {
            assert!(
                Instant::now() < deadline,
                "terminal echo never became {}",
                if enabled { "enabled" } else { "disabled" }
            );

            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Types `input` at the terminal.
    pub fn type_text(&mut self, input: &str) {
        self.master
            .write_all(input.as_bytes())
            .expect("type at the terminal");
    }

    /// Everything the terminal displayed so far. With echo off, typed
    /// input must never show up here.
    pub fn displayed(&mut self) -> String {
        let flags = fcntl(self.master.as_fd(), FcntlArg::F_GETFL).expect("read master flags");
        let nonblocking = OFlag::from_bits_truncate(flags) | OFlag::O_NONBLOCK;

        fcntl(self.master.as_fd(), FcntlArg::F_SETFL(nonblocking)).expect("set master nonblocking");

        let mut shown = Vec::new();
        let mut chunk = [0_u8; 4096];

        loop {
            match self.master.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => shown.extend_from_slice(&chunk[..count]),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                // WouldBlock is an empty terminal, and EIO is a closed one.
                Err(_) => break,
            }
        }

        String::from_utf8_lossy(&shown).into_owned()
    }
}

/// A child whose stdin is a terminal.
pub struct Prompted {
    child: Child,
    pub terminal: Terminal,
    /// The terminal's local flags before the child started. A fast
    /// binary can reach its prompt and turn echo off before the test
    /// looks, so the state to compare against is read ahead of the
    /// spawn, never after it.
    pub initial_flags: LocalFlags,
}

/// Spawns `command` with a pseudo-terminal on stdin and pipes on stdout
/// and stderr, so prompts stay capturable.
pub fn spawn(mut command: Command) -> Prompted {
    let terminal = Terminal::open();
    let stdin = terminal
        .slave
        .try_clone()
        .expect("duplicate the terminal for stdin");

    let initial_flags = terminal.local_flags();

    assert!(
        terminal.echo_enabled(),
        "a fresh pty starts with echo enabled"
    );

    let child = command
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn the binary under test on a terminal");

    Prompted {
        child,
        terminal,
        initial_flags,
    }
}

/// Runs `command` with a pseudo-terminal on stdin, stdout, and stderr,
/// and returns what the terminal displayed with the exit status. Output
/// styling follows the destination, and only a terminal shows the
/// styling a person sees.
pub fn capture_on_terminal(mut command: Command) -> (String, ExitStatus) {
    let pair = openpty(None, None).expect("open a pseudo-terminal");
    let mut master = File::from(pair.master);

    let duplicate = || Stdio::from(pair.slave.try_clone().expect("duplicate the terminal"));

    let mut child = command
        .stdin(duplicate())
        .stdout(duplicate())
        .stderr(duplicate())
        .spawn()
        .expect("spawn the binary under test on a terminal");

    // Drop every copy of the slave the test holds, the ones the command
    // keeps for the child included, so the read below ends when the
    // child exits.
    drop(command);
    drop(pair.slave);

    // Read on a thread, so a child that never exits fails the test
    // instead of blocking it forever.
    let (sender, receiver) = mpsc::channel();

    thread::spawn(move || {
        let mut displayed = Vec::new();
        let mut chunk = [0_u8; 4096];

        loop {
            match master.read(&mut chunk) {
                Ok(0) => break,
                Ok(count) => displayed.extend_from_slice(&chunk[..count]),
                Err(err) if err.kind() == ErrorKind::Interrupted => {}
                // EIO is how a pseudo-terminal reports that the last
                // writer closed it.
                Err(_) => break,
            }
        }

        let _ = sender.send(displayed);
    });

    let Ok(displayed) = receiver.recv_timeout(RUN_DEADLINE) else {
        let _ = child.kill();
        let _ = child.wait();

        panic!("the binary under test did not exit within {RUN_DEADLINE:?}");
    };

    let status = child.wait().expect("wait for the child on a terminal");

    // The terminal maps each newline to a carriage return and newline.
    (
        String::from_utf8_lossy(&displayed).replace("\r\n", "\n"),
        status,
    )
}

impl Prompted {
    /// Delivers `signal` to the child.
    pub fn signal(&self, signal: Signal) {
        let pid = i32::try_from(self.child.id()).expect("pid fits an i32");

        kill(Pid::from_raw(pid), signal).expect("signal the child");
    }

    /// Waits for the child and returns its output with the terminal, so
    /// the caller can inspect the state the child left behind.
    pub fn finish(self) -> (Run, Terminal) {
        (collect(self.child), self.terminal)
    }
}
