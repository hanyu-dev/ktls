#![doc = include_str!("../README.md")]

mod log;

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(feature = "async-io-tokio")]
use std::pin::Pin;
#[cfg(feature = "async-io-tokio")]
use std::task;

use ktls_core::utils::Buffer;
use ktls_core::{Context, Session};
#[cfg(feature = "async-io-tokio")]
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[project = StreamProj]
    /// A thin wrapper around a socket with kernel TLS (kTLS) offload configured.
    ///
    /// This implements traits [`Read`](std::io::Read) and
    /// [`Write`](std::io::Write), [`AsyncRead`](tokio::io::AsyncRead) and
    /// [`AsyncWrite`](tokio::io::AsyncWrite) (when feature `async-io-tokio` is
    /// enabled).
    ///
    /// ## Behaviours
    ///
    /// Once a TLS `close_notify` alert from the peer is received, all subsequent
    /// read operations will return EOF.
    ///
    /// Once the caller explicitly calls `(poll_)shutdown` on the stream, all
    /// subsequent write operations will return 0 bytes, indicating that the
    /// stream is closed for writing.
    ///
    /// Once the stream is being dropped, a `close_notify` alert would be sent to
    /// the peer automatically before shutting down the inner socket, according to
    /// [RFC 8446, section 6.1].
    ///
    /// The caller may call `(poll_)shutdown` on the stream to shutdown explicitly
    /// both sides of the stream. Currently, there's no way provided by this crate
    /// to shutdown the TLS stream write side only. For TLS 1.2, this is ideal since
    /// once one party sends a `close_notify` alert, *the other party MUST respond
    /// with a `close_notify` alert of its own and close down the connection
    /// immediately*, according to [RFC 5246, section 7.2.1]; for TLS 1.3, *both
    /// parties need not wait to receive a "`close_notify`" alert before
    /// closing their read side of the connection*, according to [RFC 8446, section
    /// 6.1].
    ///
    /// [RFC 5246, section 7.2.1]: https://tools.ietf.org/html/rfc5246#section-7.2.1
    /// [RFC 8446, section 6.1]: https://tools.ietf.org/html/rfc8446#section-6.1
    pub struct Stream<S: AsFd, C: Session> {
        #[pin]
        inner: S,

        // Context of the kTLS connection.
        context: Context<C>,
    }

    impl<S: AsFd, C: Session> PinnedDrop for Stream<S, C> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();

            this.context.shutdown(&*this.inner);
        }
    }
}

impl<S: AsFd, C: Session> Stream<S, C> {
    /// Creates a new kTLS stream from the given socket, TLS session and an
    /// optional buffer (may be early data received from peer during
    /// handshaking).
    ///
    /// # Prerequisites
    ///
    /// - The socket must have TLS ULP configured with
    /// [setup_ulp](ktls_core::setup_ulp).
    /// - The TLS handshake must be completed.
    pub fn new(socket: S, session: C, buffer: Option<Buffer>) -> Self {
        Self {
            inner: socket,
            context: Context::new(session, buffer),
        }
    }

    /// Returns a mutable reference to the inner socket if the TLS connection is
    /// not closed (unidirectionally or bidirectionally).
    ///
    /// This requires a mutable reference to the [`Stream`] to ensure a
    /// exclusive access to the inner socket.
    ///
    /// ## Notes
    ///
    /// * All buffered data **MUST** be properly consumed (See
    ///   [AccessRawStreamError::HasBufferedData]).
    ///
    ///   The buffered data typically consists of:
    ///
    ///   - Early data received during handshake.
    ///   - Application data received due to improper usage of
    ///     [`StreamRefMutRaw::handle_io_error`].
    ///
    /// * The caller **MAY** handle any [`io::Result`]s returned by I/O
    ///   operations on the inner socket with
    ///   [`StreamRefMutRaw::handle_io_error`].
    ///
    /// * The caller **MUST NOT** shutdown the inner socket directly, which will
    ///   lead to undefined behaviours. Instead, the caller **MAY** call
    ///   `(poll_)shutdown` explictly on the [`KtlsStream`] to gracefully
    ///   shutdown the TLS stream (with `close_notify` be sent) manually, or
    ///   just drop the stream to do automatic graceful shutdown.
    pub fn as_mut_raw(&mut self) -> Result<StreamRefMutRaw<'_, S, C>, AccessRawStreamError> {
        if let Some(buffer) = self.context.buffer_mut().drain() {
            return Err(AccessRawStreamError::HasBufferedData(buffer));
        }

        let state = self.context.state();

        if state.is_closed() {
            // Fully closed, just return error.
            return Err(AccessRawStreamError::Closed);
        }

        Ok(StreamRefMutRaw { this: self })
    }
}

macro_rules! handle_ret {
    ($this:expr, $($tt:tt)+) => {
        loop {
            let err = match $($tt)+ {
                r @ Ok(_) => return r,
                Err(err) => err,
            };

            $this.context.handle_io_error(&$this.inner, err)?;
        }
    };
}

impl<S, C> Read for Stream<S, C>
where
    S: AsFd + Read,
    C: Session,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        handle_ret!(self, {
            if self.context.state().is_read_closed() {
                return Ok(0);
            }

            let read_from_buffer = self.context.buffer_mut().read(|data| {
                let amt = buf.len().min(data.len());
                buf[..amt].copy_from_slice(&data[..amt]);
                amt
            });

            if let Some(read_from_buffer) = read_from_buffer {
                return Ok(read_from_buffer.get());
            }

            // Retry is OK, the implementation of `Read` requires no data will be
            // read into the buffer when error occurs.
            self.inner.read(buf)
        })
    }
}

impl<S, C> Stream<S, C>
where
    S: AsFd + Write,
    C: Session,
{
    /// Shuts down both read and write sides of the TLS stream.
    pub fn shutdown(&mut self) {
        self.context.shutdown(&self.inner);
    }
}

impl<S, C> Write for Stream<S, C>
where
    S: AsFd + Write,
    C: Session,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        handle_ret!(self, {
            if self.context.state().is_write_closed() {
                // Write side is closed, return EOF.
                return Ok(0);
            }

            // Retry is OK, the implementation of `Write` requires no data will
            // be written when error occurs.
            self.inner.write(buf)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        handle_ret!(self, self.inner.flush())
    }
}

#[cfg(feature = "async-io-tokio")]
macro_rules! handle_ret_async {
    ($this:expr, $($tt:tt)+) => {
        loop {
            let err = match $($tt)+ {
                r @ std::task::Poll::Pending => return r,
                r @ std::task::Poll::Ready(Ok(_)) => return r,
                std::task::Poll::Ready(Err(err)) => err,
            };

            $this.context.handle_io_error(&*$this.inner, err)?;
        }
    };
}

#[cfg(feature = "async-io-tokio")]
impl<S, C> AsyncRead for Stream<S, C>
where
    S: AsFd + AsyncRead,
    C: Session,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.context.state().is_read_closed() {
                return task::Poll::Ready(Ok(()));
            }

            this.context.buffer_mut().read(|data| {
                let amt = buf.remaining().min(data.len());
                buf.put_slice(&data[..amt]);
                amt
            });

            this.inner.as_mut().poll_read(cx, buf)
        })
    }
}

#[cfg(feature = "async-io-tokio")]
impl<S, C> AsyncWrite for Stream<S, C>
where
    S: AsFd + AsyncWrite,
    C: Session,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.context.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return task::Poll::Ready(Ok(0));
            }

            this.inner.as_mut().poll_write(cx, buf)
        })
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.context.state().is_write_closed() {
                crate::trace!("Write closed, skipping flush");

                return task::Poll::Ready(Ok(()));
            }

            this.inner.as_mut().poll_flush(cx)
        })
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        let this = self.project();

        // Notify the peer that we're going to close the write side.
        this.context.shutdown(&*this.inner);

        // Then shutdown the inner socket.
        this.inner.poll_shutdown(cx)
    }
}

/// See [`Stream::as_mut_raw`].
pub struct StreamRefMutRaw<'a, S: AsFd, C: Session> {
    this: &'a mut Stream<S, C>,
}

impl<'a, S: AsFd, C: Session> StreamRefMutRaw<'a, S, C> {
    /// Performs an I/O operation on the inner socket, handling possible errors
    /// with [`Context::handle_io_error`].
    pub fn try_io<F, R>(&mut self, mut f: F) -> io::Result<R>
    where
        F: FnMut(&mut S) -> io::Result<R>,
    {
        handle_ret!(self.this, f(&mut self.this.inner));
    }

    /// See [`Context::handle_io_error`].
    pub fn handle_io_error(&mut self, err: io::Error) -> io::Result<()> {
        self.this
            .context
            .handle_io_error(&self.this.inner, err)
    }
}

impl<S: AsFd, C: Session> AsFd for StreamRefMutRaw<'_, S, C> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.this.inner.as_fd()
    }
}

impl<S: AsFd, C: Session> AsRawFd for StreamRefMutRaw<'_, S, C> {
    fn as_raw_fd(&self) -> RawFd {
        self.this.inner.as_fd().as_raw_fd()
    }
}

#[derive(Debug)]
/// An error indicating that the inner socket cannot be accessed directly.
pub enum AccessRawStreamError {
    /// The TLS connection is fully closed (both read and write sides).
    Closed,

    /// There's still buffered data that has not been retrieved yet.
    HasBufferedData(Vec<u8>),
}
