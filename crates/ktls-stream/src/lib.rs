#![doc = include_str!("../README.md")]

mod log;
pub mod prelude {
    //! A "prelude".
    //!
    //! This prelude is similar to the standard library's prelude in that you'll
    //! almost always want to import its entire contents, but unlike the
    //! standard library's prelude you'll have to do so manually:
    //!
    //! ```
    //! # #[allow(unused_imports)]
    //! use ktls_stream::prelude::*;
    //! ```
    //!
    //! The prelude may grow over time as additional items see ubiquitous use.
    //!
    //! Generally, you don't need to add `ktls-core` as a dependency in your
    //! `Cargo.toml` unless you are implementing custom TLS session types, etc.

    pub use ktls_core::setup_ulp;
    #[cfg(feature = "probe-ktls-compatibility")]
    pub use ktls_core::{Compatibilities, Compatibility};

    pub use crate::Stream;
}

use std::io::{self, Read, Write};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

use ktls_core::{
    setup_tls_params, setup_ulp, Buffer, Context, DummyTlsSession, ExtractedSecrets,
    TlsCryptoInfoRx, TlsCryptoInfoTx, TlsSession,
};

pin_project_lite::pin_project! {
    #[derive(Debug)]
    #[project = StreamProj]
    /// A thin wrapper around a kTLS offloaded socket.
    ///
    /// This implements [`Read`](std::io::Read) and [`Write`](std::io::Write),
    /// [`AsyncRead`](tokio::io::AsyncRead) and
    /// [`AsyncWrite`](tokio::io::AsyncWrite) (when feature `async-io-tokio` is
    /// enabled).
    ///
    /// # Behaviours
    ///
    /// Once receives a `close_notify` alert from the peer, all subsequent read
    /// operations will return EOF (unless the inner buffer contains unread data);
    /// once the caller explicitly calls `(poll_)shutdown` on the stream, a
    /// `close_notify` alert would be sent to the peer and all subsequent write
    /// operations will return 0 bytes, indicating that the stream is closed for
    /// writing. When the [`Stream`] is dropped, it will also perform graceful
    /// shutdown automatically.
    ///
    /// For TLS 1.2, once one party sends a `close_notify` alert, *the other party
    /// MUST respond with a `close_notify` alert of its own and close down the
    /// connection immediately*, according to [RFC 5246, section 7.2.1]; for TLS
    /// 1.3, *both parties need not wait to receive a "`close_notify`" alert before
    /// closing their read side of the connection*, according to [RFC 8446, section
    /// 6.1].
    ///
    /// [RFC 5246, section 7.2.1]: https://tools.ietf.org/html/rfc5246#section-7.2.1
    /// [RFC 8446, section 6.1]: https://tools.ietf.org/html/rfc8446#section-6.1
    pub struct Stream<S: AsFd, C: TlsSession> {
        #[pin]
        inner: S,

        // Context of the kTLS connection.
        context: Context<C>,
    }

    impl<S: AsFd, C: TlsSession> PinnedDrop for Stream<S, C> {
        fn drop(this: Pin<&mut Self>) {
            let this = this.project();

            this.context.shutdown(&*this.inner);
        }
    }
}

impl<S: AsFd, C: TlsSession> Stream<S, C> {
    /// Constructs a new [`Stream`] from the provided `socket`, extracted TLS
    /// `secrets` and TLS `session` context. An optional `buffer` may be
    /// provided for early data received during handshake.
    ///
    /// ## Prerequisites
    ///
    /// The socket must have TLS ULP configured with [`setup_ulp`].
    ///
    /// ## Errors
    ///
    /// Unsupported protocol version or cipher suite, or failure to set up
    /// kTLS params on the socket.
    pub fn new<K, E>(
        socket: S,
        secrets: K,
        session: C,
        buffer: Option<Buffer>,
    ) -> Result<Self, ktls_core::Error>
    where
        ExtractedSecrets: TryFrom<K, Error = E>,
        ktls_core::Error: From<E>,
    {
        let ExtractedSecrets {
            tx: (seq_tx, secrets_tx),
            rx: (seq_rx, secrets_rx),
        } = ExtractedSecrets::try_from(secrets)?;

        let tls_crypto_info_tx =
            TlsCryptoInfoTx::new(session.protocol_version(), secrets_tx, seq_tx)?;

        let tls_crypto_info_rx =
            TlsCryptoInfoRx::new(session.protocol_version(), secrets_rx, seq_rx)?;

        setup_tls_params(&socket, &tls_crypto_info_tx, &tls_crypto_info_rx)?;

        Ok(Self {
            inner: socket,
            context: Context::new(session, buffer),
        })
    }

    /// Returns a [`RawStreamMut`] which provides low-level access to the
    /// inner socket.
    ///
    /// This requires a mutable reference to the [`Stream`] to ensure a
    /// exclusive access to the inner socket.
    ///
    /// ## Notes
    ///
    /// * All buffered data **MUST** be properly consumed (See
    ///   [`AccessRawStreamError::HasBufferedData`]).
    ///
    ///   The buffered data typically consists of:
    ///
    ///   - Early data received during handshake.
    ///   - Application data received due to improper usage of
    ///     [`RawStreamMut::handle_io_error`].
    ///
    /// * The caller **MAY** handle any [`io::Error`]s returned by direct I/O
    ///   operations on the inner socket with [`RawStreamMut::handle_io_error`].
    ///
    /// * The caller **MUST NOT** *shutdown* the inner socket directly, which
    ///   will lead to undefined behaviours.
    ///
    /// # Errors
    ///
    /// See [`AccessRawStreamError`].
    pub fn as_mut_raw(&mut self) -> Result<RawStreamMut<'_, S, C>, AccessRawStreamError> {
        if let Some(buffer) = self.context.buffer_mut().drain() {
            return Err(AccessRawStreamError::HasBufferedData(buffer));
        }

        if self.context.state().is_closed() {
            // Fully closed, just return error.
            return Err(AccessRawStreamError::Closed);
        }

        Ok(RawStreamMut { this: self })
    }

    #[cfg(feature = "tls13-key-update")]
    /// [`Context::refresh_traffic_keys`] against the inner socket.
    ///
    /// Use with caution, and do check [`Context::refresh_traffic_keys`] for
    /// details.
    ///
    /// # Errors
    ///
    /// See [`Context::refresh_traffic_keys`].
    pub fn refresh_traffic_keys(&mut self) -> Result<(), ktls_core::Error> {
        self.context
            .refresh_traffic_keys(&self.inner)
    }
}

impl<S> Stream<S, DummyTlsSession>
where
    S: AsFd,
{
    #[inline]
    /// Creates a new [`Stream`] with a [`DummyTlsSession`].
    ///
    /// This doesn't require the socket to have TLS ULP configured, we will
    /// configure it here.
    ///
    /// See also [`Stream::new`].
    ///
    /// ## Errors
    ///
    /// See [`Stream::new`].
    pub fn new_dummy(
        socket: S,
        secrets: ExtractedSecrets,
        session: DummyTlsSession,
        buffer: Option<Buffer>,
    ) -> Result<Self, ktls_core::Error> {
        setup_ulp(&socket)?;

        Self::new(socket, secrets, session, buffer)
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
    C: TlsSession,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        handle_ret!(self, {
            let read_from_buffer = self.context.buffer_mut().read(|data| {
                crate::trace!("Read from buffer: remaining {} bytes", data.len());

                let amt = buf.len().min(data.len());
                buf[..amt].copy_from_slice(&data[..amt]);
                amt
            });

            if let Some(read_from_buffer) = read_from_buffer {
                return Ok(read_from_buffer.get());
            }

            if self.context.state().is_read_closed() {
                crate::trace!("Read closed, returning EOF");

                return Ok(0);
            }

            // Retry is OK, the implementation of `Read` requires no data will be
            // read into the buffer when error occurs.
            self.inner.read(buf)
        })
    }
}

macro_rules! impl_shutdown {
    ($ty:ty) => {
        impl<C> Stream<$ty, C>
        where
            C: TlsSession,
        {
            /// Shuts down both read and write sides of the TLS stream.
            pub fn shutdown(&mut self) {
                let is_write_closed = self.context.state().is_write_closed();

                self.context.shutdown(&self.inner);

                if !is_write_closed {
                    let _ = self
                        .inner
                        .shutdown(std::net::Shutdown::Write);
                }
            }
        }
    };
}

impl_shutdown!(std::net::TcpStream);
impl_shutdown!(std::os::unix::net::UnixStream);

impl<S, C> Write for Stream<S, C>
where
    S: AsFd + Write,
    C: TlsSession,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        handle_ret!(self, {
            if self.context.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return Ok(0);
            }

            // Retry is OK, the implementation of `Write` requires no data will
            // be written when error occurs.
            self.inner.write(buf)
        })
    }

    fn flush(&mut self) -> io::Result<()> {
        handle_ret!(self, {
            if self.context.state().is_write_closed() {
                crate::trace!("Write closed, skipping flush");

                return Ok(());
            }

            self.inner.flush()
        })
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
impl<S, C> tokio::io::AsyncRead for Stream<S, C>
where
    S: AsFd + tokio::io::AsyncRead,
    C: TlsSession,
{
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            let read_from_buffer = this.context.buffer_mut().read(|data| {
                let amt = buf.remaining().min(data.len());

                crate::trace!(
                    "Read from buffer: remaining {} bytes, will read {} bytes",
                    data.len(),
                    amt
                );

                buf.put_slice(&data[..amt]);

                amt
            });

            if read_from_buffer.is_some() {
                return std::task::Poll::Ready(Ok(()));
            }

            if this.context.state().is_read_closed() {
                crate::trace!("Read closed, returning EOF");

                return std::task::Poll::Ready(Ok(()));
            }

            // Retry is OK, the implementation of `poll_read` requires no data will be
            // read into the buffer when error occurs.
            this.inner.as_mut().poll_read(cx, buf)
        })
    }
}

#[cfg(feature = "async-io-tokio")]
impl<S, C> tokio::io::AsyncWrite for Stream<S, C>
where
    S: AsFd + tokio::io::AsyncWrite,
    C: TlsSession,
{
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.context.state().is_write_closed() {
                crate::trace!("Write closed, returning EOF");

                return std::task::Poll::Ready(Ok(0));
            }

            this.inner.as_mut().poll_write(cx, buf)
        })
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut this = self.project();

        handle_ret_async!(this, {
            if this.context.state().is_write_closed() {
                crate::trace!("Write closed, skipping flush");

                return std::task::Poll::Ready(Ok(()));
            }

            this.inner.as_mut().poll_flush(cx)
        })
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.project();

        let is_write_closed = this.context.state().is_write_closed();

        // Notify the peer that we're going to close the write side.
        this.context.shutdown(&*this.inner);

        if is_write_closed {
            std::task::Poll::Ready(Ok(()))
        } else {
            this.inner.poll_shutdown(cx)
        }
    }
}

/// See [`Stream::as_mut_raw`].
pub struct RawStreamMut<'a, S: AsFd, C: TlsSession> {
    this: &'a mut Stream<S, C>,
}

impl<S: AsFd, C: TlsSession> RawStreamMut<'_, S, C> {
    /// Performs read operation on the inner socket, handles possible errors
    /// with [`Context::handle_io_error`] and retries the operation if the
    /// error is recoverable (see [`Context::handle_io_error`] for details).
    ///
    /// # Prerequisites
    ///
    /// The caller SHOULD NOT perform any *write* operations in `f`.
    ///
    /// # Errors
    ///
    /// - If the read side of the TLS stream is closed, this will return an EOF.
    /// - Returns the original I/O error returned by `f` that is unrecoverable.
    ///
    ///   See also [`Context::handle_io_error`].
    pub fn try_read_io<F, R>(&mut self, mut f: F) -> io::Result<R>
    where
        F: FnMut(&mut S, &mut Context<C>) -> io::Result<R>,
    {
        if self
            .this
            .context
            .state()
            .is_read_closed()
        {
            crate::trace!("Read closed, returning EOF");

            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS stream (read side) is closed",
            ));
        }

        handle_ret!(self.this, f(&mut self.this.inner, &mut self.this.context));
    }

    /// Performs write operation on the inner socket, handles possible errors
    /// with [`Context::handle_io_error`] and retries the operation if the
    /// error is recoverable (see [`Context::handle_io_error`] for details).
    ///
    /// # Prerequisites
    ///
    /// The caller SHOULD NOT perform any *read* operations in `f`.
    ///
    /// # Errors
    ///
    /// - If the write side of the TLS stream is closed, this will return an
    ///   EOF.
    /// - Returns the original I/O error returned by `f` that is unrecoverable.
    ///
    ///   See also [`Context::handle_io_error`].
    pub fn try_write_io<F, R>(&mut self, mut f: F) -> io::Result<R>
    where
        F: FnMut(&mut S, &mut Context<C>) -> io::Result<R>,
    {
        if self
            .this
            .context
            .state()
            .is_write_closed()
        {
            crate::trace!("Write closed, returning WriteZero");

            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "TLS stream (write side) is closed",
            ));
        }

        handle_ret!(self.this, f(&mut self.this.inner, &mut self.this.context));
    }

    #[inline]
    /// Since [`RawStreamMut`] provides direct access to the inner socket,
    /// the caller **MUST** handle any possible I/O errors returned by I/O
    /// operations on the inner socket with this method.
    ///
    /// See also [`Context::handle_io_error`].
    ///
    /// # Errors
    ///
    /// See [`Context::handle_io_error`].
    pub fn handle_io_error(&mut self, err: io::Error) -> io::Result<()> {
        self.this
            .context
            .handle_io_error(&self.this.inner, err)
    }
}

impl<S: AsFd, C: TlsSession> AsFd for RawStreamMut<'_, S, C> {
    #[inline]
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.this.inner.as_fd()
    }
}

impl<S: AsFd, C: TlsSession> AsRawFd for RawStreamMut<'_, S, C> {
    #[inline]
    fn as_raw_fd(&self) -> RawFd {
        self.this.inner.as_fd().as_raw_fd()
    }
}

#[non_exhaustive]
#[derive(Debug)]
/// An error indicating that the inner socket cannot be accessed directly.
pub enum AccessRawStreamError {
    /// The TLS connection is fully closed (both read and write sides).
    Closed,

    /// There's still buffered data that has not been retrieved yet.
    ///
    /// The buffered data typically consists of:
    ///
    /// - Early data received during handshake.
    /// - Application data received due to improper usage of
    ///   [`RawStreamMut::handle_io_error`].
    HasBufferedData(Vec<u8>),
}
