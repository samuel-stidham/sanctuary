//! A byte buffer the kernel keeps out of swap and that wipes itself.
//!
//! It holds the decrypted identity file for the moment it takes to
//! parse the key. Locking is best effort. A machine with no locked
//! memory allowance still unlocks its identity, and the wipe happens
//! either way.

use std::ffi::c_void;
use std::ptr::NonNull;

use nix::sys::mman::{mlock, munlock};
use zeroize::Zeroize;

/// Bytes held in locked memory when the kernel allows it.
pub struct Locked {
    bytes: Vec<u8>,
    locked: bool,
}

impl Locked {
    /// Copies `source` into a fresh buffer that is locked before any
    /// byte lands in it. The caller still owns `source` and wipes it.
    pub fn copy_of(source: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(source.len());
        let locked = region(&mut bytes).is_some_and(|(start, length)| {
            // SAFETY: the region is the buffer's own allocation, which
            // lives until `drop` unlocks it.
            unsafe { mlock(start, length) }.is_ok()
        });

        // The capacity already fits the source, so this cannot move
        // the bytes out of the locked region.
        bytes.extend_from_slice(source);

        Self { bytes, locked }
    }

    /// Whether the kernel agreed to lock the buffer.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        self.bytes.zeroize();

        if !self.locked {
            return;
        }

        if let Some((start, length)) = region(&mut self.bytes) {
            // SAFETY: this is the region `copy_of` locked. The buffer
            // never grew, so it has not moved.
            let _ = unsafe { munlock(start, length) };
        }
    }
}

/// The allocation behind `bytes`, or nothing when it has none.
fn region(bytes: &mut Vec<u8>) -> Option<(NonNull<c_void>, usize)> {
    if bytes.capacity() == 0 {
        return None;
    }

    NonNull::new(bytes.as_mut_ptr().cast()).map(|start| (start, bytes.capacity()))
}

impl std::fmt::Debug for Locked {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        out.write_str(crate::secret::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::Locked;

    #[test]
    fn the_copy_holds_the_source() {
        let locked = Locked::copy_of(b"fake-key-material");

        assert_eq!(locked.bytes(), b"fake-key-material");
    }

    #[test]
    fn an_empty_source_is_held_unlocked() {
        let locked = Locked::copy_of(b"");

        assert!(locked.bytes().is_empty());
        assert!(!locked.is_locked());
    }

    #[test]
    fn a_locked_buffer_never_formats() {
        assert_eq!(
            format!("{:?}", Locked::copy_of(b"fake-key-material")),
            "[REDACTED]"
        );
    }
}
