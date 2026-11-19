//! The no-echo line prompt.
//!
//! The terminal keeps canonical line assembly and its signal keys, with
//! echo off and CR mapped to NL. The line is read one byte at a time,
//! so the prompt never consumes input past the newline, and every
//! buffer the line outgrows is zeroed.
//!
//! A terminating signal at the prompt must put echo back and end the
//! process. Restoring alone would leave the read running with echo on,
//! and the rest of the line would be echoed. The handler therefore
//! restores the terminal and exits, and it comes down with the prompt.

use std::io::{self, IsTerminal, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicPtr, Ordering};

use nix::errno::Errno;
use nix::libc;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};
use nix::sys::termios::{InputFlags, LocalFlags, SetArg, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

use super::Error;

/// The initial capacity of the line buffer and the extra headroom added
/// on each growth.
const LINE_CHUNK: usize = 64;

/// The signals that would otherwise leave echo disabled. SIGINT and
/// SIGQUIT arrive from the keyboard, SIGTERM from a supervisor or a
/// timeout wrapper, and SIGHUP when the terminal goes away.
const SIGNALS: [Signal; 4] = [
    Signal::SIGINT,
    Signal::SIGTERM,
    Signal::SIGHUP,
    Signal::SIGQUIT,
];

/// The terminal state the signal handler restores, and the descriptor
/// it restores it on. Null while no prompt is reading.
static SAVED_STATE: AtomicPtr<libc::termios> = AtomicPtr::new(ptr::null_mut());
static SAVED_FD: AtomicI32 = AtomicI32::new(-1);

/// Prints `label` and reads one no-echo line from the terminal. `noun`
/// names what is being read, so a value prompt does not complain about
/// a passphrase.
pub fn prompt_once(label: &str, noun: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    let stdin = io::stdin();

    if !stdin.is_terminal() {
        return Err(Error::Message(
            "stdin is not a terminal: use --passphrase-file".to_owned(),
        ));
    }

    say(label);

    let entered = read_line_no_echo(stdin.as_fd());

    say("\n");

    let entered = entered.map_err(|err| Error::Message(format!("read {noun}: {err}")))?;

    if entered.is_empty() {
        return Err(Error::Message(format!("{noun} must not be empty")));
    }

    Ok(entered)
}

/// Writes prompt text to stderr, ignoring write errors the way
/// terminal prompts always do.
fn say(text: &str) {
    let mut stderr = io::stderr().lock();

    let _ = stderr.write_all(text.as_bytes());
    let _ = stderr.flush();
}

/// Why the line could not be read.
#[derive(Debug, thiserror::Error)]
enum ReadError {
    #[error("read terminal state: {}", describe(*.0))]
    State(Errno),

    #[error("disable terminal echo: {}", describe(*.0))]
    Echo(Errno),

    #[error("read line: {}", describe(*.0))]
    Line(Errno),
}

fn describe(errno: Errno) -> String {
    crate::sys::describe(&io::Error::from(errno))
}

/// Puts the terminal back, then takes the signal handler down, in that
/// order, when the prompt ends by any path.
struct Restore<'fd> {
    stdin: BorrowedFd<'fd>,
    previous: Termios,
    actions: Vec<(Signal, SigAction)>,
    saved: *mut libc::termios,
}

impl Drop for Restore<'_> {
    fn drop(&mut self) {
        let _ = tcsetattr(self.stdin, SetArg::TCSANOW, &self.previous);

        for (signal, action) in &self.actions {
            // SAFETY: this reinstalls the action that was in place
            // before the prompt, which was valid then.
            let _ = unsafe { sigaction(*signal, action) };
        }

        SAVED_STATE.store(ptr::null_mut(), Ordering::SeqCst);
        SAVED_FD.store(-1, Ordering::SeqCst);

        // SAFETY: `saved` came from `Box::into_raw` in
        // `read_line_no_echo`. The handler can no longer run, and the
        // static no longer points at it, so this is the last owner.
        drop(unsafe { Box::from_raw(self.saved) });
    }
}

/// Restores the terminal and exits. It only calls functions that are
/// safe inside a signal handler.
extern "C" fn restore_and_exit(_signal: libc::c_int) {
    let state = SAVED_STATE.load(Ordering::SeqCst);

    if !state.is_null() {
        // SAFETY: a non-null pointer is a live allocation owned by the
        // prompt that is reading, and tcsetattr only reads from it.
        unsafe {
            libc::tcsetattr(SAVED_FD.load(Ordering::SeqCst), libc::TCSANOW, state);
        }
    }

    // SAFETY: _exit is async-signal-safe and never returns.
    unsafe { libc::_exit(1) }
}

fn read_line_no_echo(stdin: BorrowedFd<'_>) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let previous = tcgetattr(stdin).map_err(ReadError::State)?;
    let saved = Box::into_raw(Box::new(libc::termios::from(previous.clone())));

    SAVED_FD.store(stdin.as_raw_fd(), Ordering::SeqCst);
    SAVED_STATE.store(saved, Ordering::SeqCst);

    let mut restore = Restore {
        stdin,
        previous: previous.clone(),
        actions: Vec::with_capacity(SIGNALS.len()),
        saved,
    };

    // Install the handler before echo goes off, never after. A signal
    // arriving in the gap between the two would find no handler, take
    // the default termination, and leave the shell with echo disabled.
    // Restoring a terminal that was never changed is harmless.
    let handler = SigAction::new(
        SigHandler::Handler(restore_and_exit),
        SaFlags::empty(),
        SigSet::empty(),
    );

    for signal in SIGNALS {
        // SAFETY: the handler only calls async-signal-safe functions,
        // and the state it reads is already in place.
        if let Ok(action) = unsafe { sigaction(signal, &handler) } {
            restore.actions.push((signal, action));
        }
    }

    let mut quiet = previous;

    quiet.local_flags.remove(LocalFlags::ECHO);
    quiet
        .local_flags
        .insert(LocalFlags::ICANON | LocalFlags::ISIG);
    quiet.input_flags.insert(InputFlags::ICRNL);

    tcsetattr(stdin, SetArg::TCSANOW, &quiet).map_err(ReadError::Echo)?;

    read_line_wiping(stdin)
}

/// Reads until a newline or end of input. The newline is not part of
/// the result. End of input before any newline returns what was read.
///
/// A read interrupted by a signal resumes, because a benign signal such
/// as a window resize must not break the prompt.
fn read_line_wiping(stdin: BorrowedFd<'_>) -> Result<Zeroizing<Vec<u8>>, ReadError> {
    let mut line = Zeroizing::new(Vec::with_capacity(LINE_CHUNK));
    let mut one = Zeroizing::new([0_u8; 1]);

    loop {
        let count = match nix::unistd::read(stdin, one.as_mut_slice()) {
            Ok(count) => count,
            Err(Errno::EINTR) => continue,
            Err(errno) => return Err(ReadError::Line(errno)),
        };

        if count == 0 || one[0] == b'\n' {
            return Ok(line);
        }

        push_wiping(&mut line, one[0]);
    }
}

/// Appends one byte to `line`. When the buffer must grow, the bytes
/// move to a new one and the outgrown buffer is zeroed.
fn push_wiping(line: &mut Zeroizing<Vec<u8>>, next: u8) {
    if line.len() == line.capacity() {
        let mut grown = Zeroizing::new(Vec::with_capacity(line.capacity() * 2 + LINE_CHUNK));

        grown.extend_from_slice(line);

        // The outgrown buffer is zeroed as it is dropped here.
        *line = grown;
    }

    line.push(next);
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{LINE_CHUNK, push_wiping};

    #[test]
    fn push_wiping_grows_and_keeps_the_line() {
        let mut line = Zeroizing::new(Vec::with_capacity(LINE_CHUNK));
        let text: Vec<u8> = (0..1000_u32)
            .map(|index| b'a' + (index % 26) as u8)
            .collect();

        for byte in &text {
            let full = line.len() == line.capacity();
            let before = line.capacity();

            push_wiping(&mut line, *byte);

            if full {
                assert_eq!(line.capacity(), before * 2 + LINE_CHUNK);
            }
        }

        assert_eq!(*line, text);
    }
}
