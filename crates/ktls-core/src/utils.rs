//! Utilities

use std::fmt;
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;

#[derive(Clone, Default)]
/// A simple buffer with a read offset.
pub struct Buffer {
    /// The inner buffer data.
    inner: Vec<u8>,

    /// The number of initialized but unfilled bytes in the inner buffer.
    unfilled_initialized: usize,

    /// Read offset of the buffer.
    offset: usize,
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Buffer")
            .field("len", &self.inner.len())
            .field("capacity", &self.inner.capacity())
            .field("unfilled_initialized", &self.unfilled_initialized)
            .field("offset", &self.offset)
            .finish()
    }
}

impl From<Vec<u8>> for Buffer {
    #[inline]
    fn from(buffer: Vec<u8>) -> Self {
        Self::new(buffer)
    }
}

impl Buffer {
    #[inline]
    #[must_use]
    /// Creates a new [`Buffer`] from the given bytes slice.
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            inner: buffer,
            unfilled_initialized: 0,
            offset: 0,
        }
    }

    #[must_use]
    /// Creates an empty [`Buffer`].
    pub const fn empty() -> Self {
        Self {
            inner: Vec::new(),
            unfilled_initialized: 0,
            offset: 0,
        }
    }

    #[track_caller]
    /// Reads the unread part of the buffer with the provided F, and advances
    /// the read offset by the number of bytes read.
    ///
    /// Returns the number of bytes read by `f`.
    ///
    /// # Panics
    ///
    /// Panics if the closure returns an invalid read count.
    pub fn read<F>(&mut self, f: F) -> Option<NonZeroUsize>
    where
        F: FnOnce(&[u8]) -> usize,
    {
        if self.inner.is_empty() {
            // Empty buffer, nothing to read.

            return None;
        }

        let Some((_, unread)) = self.inner.split_at_checked(self.offset) else {
            unreachable!(
                "The offset is always within the buffer length, but it is not: offset = {}, len = \
                 {}",
                self.offset,
                self.inner.len()
            );
        };

        if unread.is_empty() {
            // All data has been read, reset the buffer.
            self.reset();

            return None;
        }

        let has_read = NonZeroUsize::new(f(unread));

        match has_read {
            Some(n) if n.get() <= unread.len() => {
                // Advance the read offset, ensuring it does not exceed the buffer
                // length.
                self.offset = self.offset.saturating_add(n.get());
            }
            Some(n) => panic!(
                "The closure read more bytes than available: read = {}, available = {}",
                n,
                unread.len()
            ),
            None => {}
        }

        has_read
    }

    #[inline]
    #[must_use]
    /// Returns the unread part of the buffer as a byte slice.
    pub fn unread(&self) -> &[u8] {
        &self.inner[self.offset..]
    }

    #[inline]
    /// Drains the inner buffer data, clearing the buffer but does not change
    /// its capacity, and returns the drained data.
    pub fn drain(&mut self) -> Option<Vec<u8>> {
        if self.unread().is_empty() {
            None
        } else {
            let drained = self.unread().to_vec();

            // Reset the buffer after draining.
            self.reset();

            Some(drained)
        }
    }

    #[inline]
    /// Reserves capacity for at least `additional` more bytes.
    pub(crate) fn reserve(&mut self, additional: usize) {
        self.inner.reserve(additional);
    }

    #[inline]
    /// Returns a mutable reference to the unfilled part of the buffer without
    /// ensuring that it has been fully initialized.
    pub(crate) fn unfilled_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        self.unfilled_initialized = 0;

        self.inner.spare_capacity_mut()
    }

    #[inline]
    /// Returns a reference to the unfilled but initialized part of the buffer.
    pub(crate) fn unfilled_initialized(&self) -> &[u8] {
        #[allow(unsafe_code)]
        // SAFETY: We have ensured that the unfilled part is initialized.
        unsafe {
            std::slice::from_raw_parts(
                self.inner
                    .as_ptr()
                    .add(self.inner.len()),
                self.unfilled_initialized,
            )
        }
    }

    #[allow(unsafe_code)]
    #[inline]
    /// Marks additional `cnt` bytes of uninitialized part of the inner buffer
    /// as initialized.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the first `cnt` bytes of the spare capacity
    /// have been initialized, and that `self.initialized + cnt` does not exceed
    /// the capacity of the inner buffer.
    ///
    /// It is recommended to update the initialized bytes after acquiring (via
    /// [`Spare::unfilled_mut`]) and writing to the unfilled part of the
    /// buffer.
    pub(crate) unsafe fn assume_init_additional(&mut self, cnt: usize) {
        let unfilled_initialized = self.unfilled_initialized + cnt;

        debug_assert!(self.inner.len() + unfilled_initialized <= self.inner.capacity());

        self.unfilled_initialized = unfilled_initialized;
    }

    #[inline]
    /// Marks all initialized spare capacity as filled.
    pub(crate) fn set_filled_all(&mut self) {
        let initialized = self.inner.len() + self.unfilled_initialized;

        debug_assert!(initialized <= self.inner.capacity());

        #[allow(unsafe_code)]
        // SAFETY: We have ensured that the unfilled part is initialized, and the length is valid.
        unsafe {
            self.inner.set_len(initialized);
        };
    }

    #[inline]
    /// Resets the buffer, clearing the inner data and resetting the read
    /// offset.
    fn reset(&mut self) {
        self.inner.truncate(0);
        self.inner.shrink_to(65536);
        self.offset = 0;
    }
}
