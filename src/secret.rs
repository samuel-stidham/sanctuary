//! [`Value`], the only type in this crate allowed to hold plaintext
//! secret bytes, and the wiping reader that carries them in.
//!
//! The bytes are private. Plaintext leaves only through
//! [`Value::expose`]. `Debug`, `Display`, and `Serialize` all render the
//! redaction marker, so formatting, logging, and JSON output cannot leak
//! by accident. The storage is zeroed when the value is dropped, so a
//! plaintext copy does not outlive the span that needed it.
//!
//! Never add another exit, and never derive `Clone`: a value that cannot
//! be copied cannot leave a copy behind.

use std::fmt;
use std::io::{self, ErrorKind, Read};
use std::mem;
use std::os::fd::BorrowedFd;

use nix::errno::Errno;
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};

use serde::{Serialize, Serializer};
use zeroize::{Zeroize, Zeroizing};

/// What every rendering of a [`Value`] prints instead of its bytes.
pub const REDACTED: &str = "[REDACTED]";

/// The initial size of the read buffer and the extra headroom added on
/// each growth.
const READ_CHUNK: usize = 512;

/// Plaintext secret bytes behind a redacting wall.
pub struct Value(Zeroizing<Vec<u8>>);

impl Value {
    /// Copies `plaintext` into a value. The caller keeps ownership of
    /// its slice and should zero it when it can.
    pub fn new(plaintext: &[u8]) -> Self {
        Self(Zeroizing::new(plaintext.to_vec()))
    }

    /// Returns the plaintext bytes. This is the only plaintext exit.
    /// Call it as late as possible. The call sites are the reveal
    /// output, the exec environment, the envelope seal path, and the
    /// init self-test.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Zeroes the held plaintext now rather than at drop. It cuts the
    /// in-memory lifetime of a decrypted value down to the span the
    /// caller needs. It is safe to call more than once, and
    /// [`Value::expose`] returns nothing afterward.
    pub fn wipe(&mut self) {
        self.0.zeroize();
    }
}

impl From<Zeroizing<Vec<u8>>> for Value {
    /// Takes ownership of an already-wiping buffer without copying it.
    fn from(plaintext: Zeroizing<Vec<u8>>) -> Self {
        Self(plaintext)
    }
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED)
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(REDACTED)
    }
}

/// Reads all of `reader`, zeroing each intermediate buffer it outgrows.
///
/// A plain `read_to_end` leaves those grown-past buffers on the heap
/// unwiped, which for secret input means an unzeroed copy of the
/// plaintext lingers until the allocator reuses it. On a read error the
/// partial content is wiped and nothing is returned, so a half-read
/// secret never survives the failure. The returned buffer wipes itself
/// when dropped.
pub fn read_all_wiping(mut reader: impl Read) -> io::Result<Zeroizing<Vec<u8>>> {
    // The buffer is always full length and zero-filled past `filled`,
    // so growth and the final trim never touch uninitialized memory.
    let mut buffer = Zeroizing::new(vec![0_u8; READ_CHUNK]);
    let mut filled = 0;

    loop {
        if filled == buffer.len() {
            // Dropping the outgrown buffer here is safe: it comes back
            // already zeroed.
            drop(grow_wiping(&mut buffer));
        }

        match reader.read(&mut buffer[filled..]) {
            Ok(0) => {
                // Wipe the unused tail, so scratch a reader may have
                // left past its reported count does not survive.
                buffer[filled..].zeroize();
                buffer.truncate(filled);

                return Ok(buffer);
            }
            Ok(count) => filled += count,
            // A signal that interrupts the read is not a failure.
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            // `buffer` wipes its whole length as it drops.
            Err(err) => return Err(err),
        }
    }
}

/// Reads a descriptor with no buffer of its own between the kernel and
/// the caller.
///
/// The standard handle for stdin reads through a process-wide buffer
/// that nothing wipes. Secret input read that way would leave a copy
/// behind until the process ends. Each read here lands straight in the
/// caller's buffer, and [`read_all_wiping`] wipes that.
#[derive(Debug)]
pub struct Unbuffered<'fd>(pub BorrowedFd<'fd>);

impl Read for Unbuffered<'_> {
    /// Reads once, waiting first when the descriptor has nothing yet.
    ///
    /// A caller can hand over a pipe in non-blocking mode, as some
    /// process supervisors do. A read then reports that it would block
    /// while the writer is still at work. That is no failure and no end
    /// of input, so this waits until the pipe is readable or closed.
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            match nix::unistd::read(self.0, buffer) {
                Err(Errno::EAGAIN) => {
                    let mut waiting = [PollFd::new(self.0, PollFlags::POLLIN)];

                    match poll(&mut waiting, PollTimeout::NONE) {
                        Ok(_) | Err(Errno::EINTR) => {}
                        Err(errno) => return Err(io::Error::from(errno)),
                    }
                }
                result => return result.map_err(io::Error::from),
            }
        }
    }
}

/// Moves `buffer` into a larger allocation and returns the outgrown one
/// with every byte zeroed.
fn grow_wiping(buffer: &mut Vec<u8>) -> Vec<u8> {
    let mut grown = vec![0_u8; buffer.len() * 2 + READ_CHUNK];

    grown[..buffer.len()].copy_from_slice(buffer);

    let mut outgrown = mem::replace(buffer, grown);

    outgrown.as_mut_slice().zeroize();

    outgrown
}

#[cfg(test)]
mod tests {
    use std::io::{self, Cursor, ErrorKind, Read};

    use zeroize::Zeroize;

    use super::{READ_CHUNK, REDACTED, Unbuffered, Value, grow_wiping, read_all_wiping};

    #[test]
    fn an_unbuffered_read_waits_on_a_pipe_that_is_not_blocking() {
        use std::io::Write;
        use std::os::fd::AsFd;

        use nix::fcntl::{FcntlArg, OFlag, fcntl};

        let (reader, mut writer) = std::io::pipe().expect("pipe");

        fcntl(reader.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK)).expect("set non-blocking");

        let slow = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            writer.write_all(b"fake-first-").expect("write");
            std::thread::sleep(std::time::Duration::from_millis(150));
            writer.write_all(b"half").expect("write");
        });

        let value = read_all_wiping(Unbuffered(reader.as_fd())).expect("read");

        slow.join().expect("writer");

        assert_eq!(*value, b"fake-first-half");
    }

    #[test]
    fn an_unbuffered_read_takes_no_more_than_it_is_asked_for() {
        use std::io::Write;
        use std::os::fd::AsFd;

        let (reader, mut writer) = std::io::pipe().expect("pipe");
        let content: Vec<u8> = (0..3000_u32)
            .map(|index| b'a' + (index % 26) as u8)
            .collect();

        writer.write_all(&content).expect("write");
        drop(writer);

        // The first read asks for four bytes and gets four. A buffered
        // reader would have taken everything the pipe held.
        let mut first = [0_u8; 4];
        let mut unbuffered = Unbuffered(reader.as_fd());

        assert_eq!(unbuffered.read(&mut first).expect("read"), 4);
        assert_eq!(first, content[..4]);

        let rest = read_all_wiping(Unbuffered(reader.as_fd())).expect("read the rest");

        assert_eq!(*rest, content[4..]);
    }

    // Obviously fake test material, never a real secret.
    const FAKE_PLAINTEXT: &str = "fake-test-secret-value-not-real";

    fn fake() -> Value {
        Value::new(FAKE_PLAINTEXT.as_bytes())
    }

    /// A reader that yields `content` and then fails with `kind`.
    struct FailsAfter {
        content: Cursor<Vec<u8>>,
        kind: ErrorKind,
    }

    impl Read for FailsAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            match self.content.read(buf)? {
                0 => Err(io::Error::new(self.kind, "boom")),
                count => Ok(count),
            }
        }
    }

    // Go: TestSecretValueNeverLeaks
    #[test]
    fn value_never_leaks_through_formatting() {
        let value = fake();

        for rendered in [
            format!("{value}"),
            format!("{value:?}"),
            format!("{value:#?}"),
            format!("{value:>40}"),
            value.to_string(),
        ] {
            assert!(
                !rendered.contains(FAKE_PLAINTEXT),
                "plaintext leaked: {rendered}"
            );
            assert!(
                rendered.contains(REDACTED),
                "redaction marker missing: {rendered}"
            );
        }
    }

    // Go: TestSecretValueUnexportedFieldNeverLeaks
    //
    // A value held in another type's private field redacts the same
    // way, because a derived Debug calls the value's own.
    #[test]
    fn value_in_a_private_field_never_leaks() {
        #[derive(Debug)]
        struct Holder {
            #[allow(dead_code)]
            value: Value,
        }

        let holder = Holder { value: fake() };

        for rendered in [format!("{holder:?}"), format!("{holder:#?}")] {
            assert!(
                !rendered.contains(FAKE_PLAINTEXT),
                "plaintext leaked: {rendered}"
            );
            // The decimal byte rendering is the other shape a leak takes.
            assert!(!rendered.contains("102, 97, 107"), "byte leak: {rendered}");
            assert!(rendered.contains(REDACTED));
        }
    }

    // Go: TestMarshalJSONExactOutput
    #[test]
    fn serializes_as_the_marker() {
        #[derive(serde::Serialize)]
        struct Wrapper {
            value: Value,
        }

        assert_eq!(
            serde_json::to_string(&fake()).expect("serialize a value"),
            "\"[REDACTED]\""
        );
        assert_eq!(
            serde_json::to_string(&Wrapper { value: fake() }).expect("serialize a wrapper"),
            "{\"value\":\"[REDACTED]\"}"
        );
    }

    // Go: TestExposeReturnsPlaintext
    #[test]
    fn expose_returns_plaintext() {
        assert_eq!(fake().expose(), FAKE_PLAINTEXT.as_bytes());
    }

    // Go: TestEmptyValue
    #[test]
    fn empty_value() {
        let value = Value::new(&[]);

        assert!(value.expose().is_empty());
        assert_eq!(value.to_string(), REDACTED);
    }

    // Go: TestNewCopiesInput
    //
    // Mutating the caller's slice must not change the held value.
    #[test]
    fn new_copies_input() {
        let mut input = FAKE_PLAINTEXT.as_bytes().to_vec();
        let value = Value::new(&input);

        input.fill(b'x');

        assert_eq!(value.expose(), FAKE_PLAINTEXT.as_bytes());
    }

    // Go: TestDestroyZeroesPlaintext
    #[test]
    fn wipe_drops_the_plaintext() {
        let mut value = fake();

        value.wipe();

        assert!(
            value.expose().is_empty(),
            "wipe must leave nothing to expose"
        );
    }

    // Go: TestDestroyIsIdempotent
    #[test]
    fn wipe_is_idempotent() {
        let mut value = fake();

        value.wipe();
        value.wipe();

        assert!(value.expose().is_empty());
    }

    // Go: TestDestroyWipesCopies, TestExposeAliasesInternalStorage
    //
    // The Go value can be copied, and its copies share one backing
    // array, so one Destroy must wipe them all. Here a value cannot be
    // copied at all, so there is never a second holder to wipe. Moving
    // is the only way to hand one on, and the moved-from name is gone.
    #[test]
    fn a_value_moves_and_is_never_copied() {
        fn assert_not_clone<T>()
        where
            T: ?Sized,
        {
            // Resolves to the blanket impl only when T is not Clone.
            trait NotClone<Marker> {
                const OK: () = ();
            }

            impl<T: ?Sized> NotClone<()> for T {}

            struct IsClone;

            impl<T: Clone> NotClone<IsClone> for T {}

            let () = <T as NotClone<_>>::OK;
        }

        assert_not_clone::<Value>();

        let value = fake();
        let moved = value;

        assert_eq!(moved.expose(), FAKE_PLAINTEXT.as_bytes());
    }

    // Go: TestZeroBytes
    #[test]
    fn zeroize_zeroes_a_buffer() {
        let mut buffer = [1_u8, 2, 3];

        buffer.zeroize();

        assert_eq!(buffer, [0, 0, 0]);
    }

    // Go: TestReadAllWiping
    //
    // The reader returns the exact input across sizes that span its
    // growth boundary.
    #[test]
    fn read_all_wiping_returns_exact_input() {
        for size in [0, 1, 511, 512, 513, 1536, 5000] {
            let want = vec![b'x'; size];
            let got = read_all_wiping(Cursor::new(want.clone())).expect("read");

            assert_eq!(*got, want, "size {size}");
        }
    }

    // Go: TestReadAllWipingSurfacesReadError, TestReadAllWipingReturnsNothingOnError
    #[test]
    fn read_all_wiping_surfaces_a_read_error() {
        let failing = FailsAfter {
            content: Cursor::new(vec![b'x'; 700]),
            kind: ErrorKind::Other,
        };
        let err = read_all_wiping(failing).expect_err("a failed read must not return content");

        assert!(err.to_string().contains("boom"));
    }

    // Go: TestReadAllWipingTreatsWrappedEOFAsFailure
    //
    // Only a clean end of input is success. An error that reports the
    // stream ended early is a genuine failure, and reading it as a clean
    // end would silently hand back truncated secret data.
    #[test]
    fn read_all_wiping_treats_an_unexpected_eof_error_as_failure() {
        let torn = FailsAfter {
            content: Cursor::new(vec![b'x'; 100]),
            kind: ErrorKind::UnexpectedEof,
        };
        let err = read_all_wiping(torn).expect_err("a torn stream must not read as complete");

        assert_eq!(
            err.kind(),
            ErrorKind::UnexpectedEof,
            "the cause must stay inspectable"
        );
    }

    // An interrupted read is retried, not reported.
    #[test]
    fn read_all_wiping_retries_an_interrupted_read() {
        struct InterruptedOnce {
            content: Cursor<Vec<u8>>,
            interrupted: bool,
        }

        impl Read for InterruptedOnce {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if !self.interrupted {
                    self.interrupted = true;

                    return Err(io::Error::from(ErrorKind::Interrupted));
                }

                self.content.read(buf)
            }
        }

        let reader = InterruptedOnce {
            content: Cursor::new(vec![b'x'; 10]),
            interrupted: false,
        };

        assert_eq!(*read_all_wiping(reader).expect("read"), vec![b'x'; 10]);
    }

    // Go: TestReadAllWipingZeroesOutgrownBuffer
    //
    // After the reader outgrows a buffer, that buffer's bytes are zeroed
    // rather than left holding a secret prefix for the allocator.
    #[test]
    fn grow_wiping_zeroes_the_outgrown_buffer() {
        let mut buffer = vec![b'x'; READ_CHUNK];

        let outgrown = grow_wiping(&mut buffer);

        assert_eq!(
            outgrown,
            vec![0_u8; READ_CHUNK],
            "the outgrown buffer must be zeroed"
        );
        assert_eq!(buffer.len(), READ_CHUNK * 3, "the buffer must have grown");
        assert_eq!(
            buffer[..READ_CHUNK],
            vec![b'x'; READ_CHUNK],
            "content must survive growth"
        );
        assert!(buffer[READ_CHUNK..].iter().all(|byte| *byte == 0));
    }
}
