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
    /// Creates a new [`Buffer`] from the given vec.
    pub fn new(buffer: Vec<u8>) -> Self {
        Self {
            inner: buffer,
            unfilled_initialized: 0,
            offset: 0,
        }
    }

    #[inline]
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
            Some(n) => unreachable!(
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
    #[must_use]
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

        assert!(self.inner.len() + unfilled_initialized <= self.inner.capacity());

        self.unfilled_initialized = unfilled_initialized;
    }

    #[inline]
    /// Marks all initialized spare capacity as filled.
    pub(crate) fn set_filled_all(&mut self) {
        let initialized = self.inner.len() + self.unfilled_initialized;

        assert!(initialized <= self.inner.capacity());

        #[allow(unsafe_code)]
        // SAFETY: We have ensured that the unfilled part is initialized, and the length is valid.
        unsafe {
            self.inner.set_len(initialized);
        };

        self.unfilled_initialized = 0;
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

#[cfg(test)]
#[allow(unsafe_code)]
#[allow(clippy::redundant_closure_for_method_calls)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_new() {
        let data = vec![1, 2, 3, 4, 5];
        let buffer = Buffer::new(data.clone());

        assert_eq!(buffer.unread(), &data);
        assert_eq!(buffer.offset, 0);
        assert_eq!(buffer.unfilled_initialized, 0);
    }

    #[test]
    fn test_buffer_empty() {
        let buffer = Buffer::empty();

        assert!(buffer.unread().is_empty());
        assert_eq!(buffer.offset, 0);
        assert_eq!(buffer.unfilled_initialized, 0);
        assert_eq!(buffer.inner.capacity(), 0);
    }

    #[test]
    fn test_buffer_from_vec() {
        let data = vec![10, 20, 30];
        let buffer: Buffer = data.clone().into();

        assert_eq!(buffer.unread(), &data);
        assert_eq!(buffer.offset, 0);
    }

    #[test]
    fn test_buffer_read_empty() {
        let mut buffer = Buffer::empty();

        let result = buffer.read(|data| {
            assert!(data.is_empty());
            0
        });

        assert!(result.is_none());
    }

    #[test]
    fn test_buffer_read_partial() {
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5]);

        // Read first 3 bytes
        let result = buffer.read(|data| {
            assert_eq!(data, &[1, 2, 3, 4, 5]);
            3
        });

        assert_eq!(result.unwrap().get(), 3);
        assert_eq!(buffer.unread(), &[4, 5]);
        assert_eq!(buffer.offset, 3);
    }

    #[test]
    fn test_buffer_read_full() {
        let mut buffer = Buffer::new(vec![1, 2, 3]);

        // Read all bytes
        let result = buffer.read(|data| {
            assert_eq!(data, &[1, 2, 3]);
            3
        });

        assert_eq!(result.unwrap().get(), 3);
        assert!(buffer.unread().is_empty());
        assert_eq!(buffer.offset, 3);
    }

    #[test]
    fn test_buffer_read_zero_bytes() {
        let mut buffer = Buffer::new(vec![1, 2, 3]);

        let result = buffer.read(|_data| 0);

        assert!(result.is_none());
        assert_eq!(buffer.unread(), &[1, 2, 3]);
        assert_eq!(buffer.offset, 0);
    }

    #[test]
    fn test_buffer_read_multiple_calls() {
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5, 6]);

        // First read
        let result1 = buffer.read(|data| {
            assert_eq!(data, &[1, 2, 3, 4, 5, 6]);
            2
        });
        assert_eq!(result1.unwrap().get(), 2);
        assert_eq!(buffer.unread(), &[3, 4, 5, 6]);

        // Second read
        let result2 = buffer.read(|data| {
            assert_eq!(data, &[3, 4, 5, 6]);
            3
        });
        assert_eq!(result2.unwrap().get(), 3);
        assert_eq!(buffer.unread(), &[6]);

        // Third read (remaining)
        let result3 = buffer.read(|data| {
            assert_eq!(data, &[6]);
            1
        });
        assert_eq!(result3.unwrap().get(), 1);
        assert!(buffer.unread().is_empty());
    }

    #[test]
    fn test_buffer_read_until_empty_resets() {
        let mut buffer = Buffer::new(vec![1, 2, 3]);

        // Read all data
        let _ = buffer.read(|data| data.len());

        // Buffer should still have offset set
        assert_eq!(buffer.offset, 3);
        assert!(buffer.unread().is_empty());

        // Next read should reset and return None
        let result = buffer.read(|_| 0);

        assert!(result.is_none());
        assert_eq!(buffer.offset, 0);
        assert_eq!(buffer.inner.len(), 0); // Buffer is reset
    }

    #[test]
    #[should_panic(expected = "The closure read more bytes than available")]
    fn test_buffer_read_panic_read_too_much() {
        let mut buffer = Buffer::new(vec![1, 2, 3]);

        // Try to read more bytes than available
        buffer.read(|data| {
            assert_eq!(data.len(), 3);
            4 // This should panic
        });
    }

    #[test]
    fn test_buffer_unread() {
        let buffer = Buffer::new(vec![1, 2, 3, 4, 5]);
        assert_eq!(buffer.unread(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_buffer_unread_after_partial_read() {
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5]);

        // Read 2 bytes
        let _ = buffer.read(|_| 2);

        assert_eq!(buffer.unread(), &[3, 4, 5]);
    }

    #[test]
    fn test_buffer_drain_empty() {
        let mut buffer = Buffer::empty();

        let drained = buffer.drain();
        assert!(drained.is_none());
    }

    #[test]
    fn test_buffer_drain_with_data() {
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5]);

        let drained = buffer.drain();
        assert_eq!(drained.unwrap(), vec![1, 2, 3, 4, 5]);

        // Buffer should be reset after drain
        assert!(buffer.unread().is_empty());
        assert_eq!(buffer.offset, 0);
        assert_eq!(buffer.inner.len(), 0);
    }

    #[test]
    fn test_buffer_drain_after_partial_read() {
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5]);

        // Read first 2 bytes
        let _ = buffer.read(|_| 2);

        let drained = buffer.drain();
        assert_eq!(drained.unwrap(), vec![3, 4, 5]); // Only unread data

        // Buffer should be reset
        assert!(buffer.unread().is_empty());
        assert_eq!(buffer.offset, 0);
    }

    #[test]
    fn test_buffer_drain_fully_read() {
        let mut buffer = Buffer::new(vec![1, 2, 3]);

        // Read all data
        let _ = buffer.read(|data| data.len());

        let drained = buffer.drain();
        assert!(drained.is_none()); // Nothing to drain
    }

    #[test]
    fn test_buffer_reserve() {
        let mut buffer = Buffer::empty();
        let initial_capacity = buffer.inner.capacity();

        buffer.reserve(100);
        assert!(buffer.inner.capacity() >= initial_capacity + 100);
    }

    #[test]
    fn test_buffer_unfilled_mut() {
        let mut buffer = Buffer::empty();
        buffer.reserve(10);

        let unfilled = buffer.unfilled_mut();
        assert_eq!(unfilled.len(), 10);
        assert_eq!(buffer.unfilled_initialized, 0);

        unsafe { buffer.assume_init_additional(5) };
        assert_eq!(buffer.unfilled_initialized, 5);

        let unfilled = buffer.unfilled_mut();
        assert!(!unfilled.is_empty());
        assert_eq!(buffer.unfilled_initialized, 0); // Should be reset to 0
    }

    #[test]
    fn test_buffer_unfilled_initialized_empty() {
        let buffer = Buffer::empty();
        let unfilled_init = buffer.unfilled_initialized();
        assert!(unfilled_init.is_empty());
    }

    #[test]
    fn test_buffer_assume_init_additional() {
        let mut buffer = Buffer::empty();
        buffer.reserve(10);

        // Simulate writing to unfilled part
        unsafe {
            buffer.assume_init_additional(5);
        }

        assert_eq!(buffer.unfilled_initialized, 5);

        let unfilled_init = buffer.unfilled_initialized();
        assert_eq!(unfilled_init.len(), 5);
    }

    #[test]
    fn test_buffer_set_filled_all() {
        let mut buffer = Buffer::empty();

        buffer.reserve(10);

        unsafe {
            buffer.assume_init_additional(3);
        }

        assert_eq!(buffer.inner.len(), 0);

        buffer.set_filled_all();

        assert_eq!(buffer.inner.len(), 3);
        assert_eq!(buffer.unfilled_initialized, 0);
    }

    #[test]
    fn test_buffer_complex_workflow() {
        // Test a complex workflow that uses multiple methods
        let mut buffer = Buffer::new(vec![1, 2, 3, 4, 5]);

        // Read some data
        let _ = buffer.read(|_| 2);
        assert_eq!(buffer.unread(), &[3, 4, 5]);

        // Reserve more space
        buffer.reserve(10);

        // Get unfilled space and mark some as initialized
        let _unfilled = buffer.unfilled_mut();
        unsafe {
            buffer.assume_init_additional(2);
        }

        // Set the initialized data as filled
        buffer.set_filled_all();

        // The buffer should now contain original unread data plus the new filled data
        assert!(buffer.unread().len() >= 3); // At least the original unread data

        // Drain everything
        let drained = buffer.drain();
        assert!(drained.is_some());
        assert!(buffer.unread().is_empty());
    }
}
