//! Kernel TLS connection context.

use std::io;
use std::os::fd::{AsFd, AsRawFd};

use bitfield_struct::bitfield;

use crate::error::{Error, InvalidMessage, PeerMisbehaved, Result};
use crate::ffi::{recv_tls_record, send_tls_control_message};
use crate::tls::{
    AlertDescription, AlertLevel, ContentType, HandshakeType, KeyUpdateRequest, Peer,
    ProtocolVersion, TlsSession,
};
use crate::utils::Buffer;

#[derive(Debug)]
/// The context for managing a kTLS connection.
pub struct Context<C: TlsSession> {
    // State of the current kTLS connection
    state: State,

    // Shared buffer
    buffer: Buffer,

    // TLS session
    session: C,
}

impl<C: TlsSession> Context<C> {
    /// Creates a new kTLS context with the given TLS session and optional
    /// buffer (can be TLS early data received from peer during handshake, or a
    /// pre-allocated buffer).
    pub fn new(session: C, buffer: Option<Buffer>) -> Self {
        Self {
            state: State::new(),
            buffer: buffer.unwrap_or_default(),
            session,
        }
    }

    #[inline]
    /// Returns the current kTLS connection state.
    pub const fn state(&self) -> &State {
        &self.state
    }

    #[inline]
    /// Returns a reference to the buffer.
    pub const fn buffer(&self) -> &Buffer {
        &self.buffer
    }

    #[inline]
    /// Returns a mutable reference to the buffer.
    pub const fn buffer_mut(&mut self) -> &mut Buffer {
        &mut self.buffer
    }

    #[track_caller]
    #[cfg(feature = "tls13-key-update")]
    /// Sends a TLS 1.3 `key_update` message to refresh a connection's keys.
    ///
    /// This call refreshes our encryption keys. Once the peer receives the
    /// message, it refreshes _its_ encryption and decryption keys and sends
    /// a response. Once we receive that response, we refresh our decryption
    /// keys to match. At the end of this process, keys in both directions
    /// have been refreshed.
    ///
    /// # Notes
    ///
    /// Note that TLS implementations (including kTLS) may enforce limits on the
    /// number of `key_update` messages allowed on a given connection to
    /// prevent denial of service. Therefore, this should be called
    /// sparingly.
    ///
    /// Since the kernel will never implicitly and automatically trigger key
    /// updates according to the selected cipher suite's cryptographic
    /// constraints, the application is responsible for calling this method
    /// as needed to maintain security.
    ///
    /// Only Linux 6.13 or later supports TLS 1.3 rekey, see [the commit], and
    /// we gate this method behind feature flag `tls13-key-update`. This method
    /// might return an error `EBUSY`, which most likely indicates that the
    /// running kernel does not support this feature.
    ///
    /// # Known Issues
    ///
    /// Under the condition that both parties are kTLS offloaded and the
    /// server uses the Tokio asynchronous runtime, if the server initiates a
    /// `KeyUpdate` by calling this method and then immediately performs a read
    /// I/O operation, the program will hang (the read I/O operation returns
    /// EAGAIN but the task waker does not seem to be registered correctly).
    /// This issue needs further investigation.
    ///
    /// # Errors
    ///
    /// - Updating the TX secret fails.
    /// - Sending the `KeyUpdate` message fails.
    /// - Setting the TX secret on the socket fails.
    ///
    /// [the commit]: https://github.com/torvalds/linux/commit/47069594e67e882ec5c1d8d374f6aab037511509
    pub fn refresh_traffic_keys<S: AsFd>(&mut self, socket: &S) -> Result<()> {
        crate::trace!("Trigger traffic keys refreshing...");

        if self.session.protocol_version() != ProtocolVersion::TLSv1_3 {
            crate::warn!(
                "Key update is only supported by TLS 1.3, current: {:?}",
                self.session.protocol_version()
            );

            return Ok(());
        }

        let tls_crypto_info_tx = match self.session.update_tx_secret() {
            Ok(tx) => tx,
            Err(error) => {
                // TODO: should we abort the connection here or just keep using the old key?

                return self.abort(socket, error, AlertDescription::InternalError);
            }
        };

        if let Err(error) = send_tls_control_message(
            socket.as_fd().as_raw_fd(),
            ContentType::Handshake,
            &mut [
                HandshakeType::KeyUpdate.to_int(), // typ
                0,
                0,
                1, // length
                KeyUpdateRequest::UpdateRequested.to_int(),
            ],
        )
        .map_err(Error::KeyUpdateFailed)
        {
            // Failed to notify the peer, abort the connection.
            crate::error!("Failed to send KeyUpdate message: {error}");

            return self.abort(socket, error, AlertDescription::InternalError);
        }

        if let Err(error) = tls_crypto_info_tx.set(socket) {
            // Failed to update tx secret, abort the connection.
            crate::error!("Failed to set TX secret: {error}");

            return self.abort(socket, error, AlertDescription::InternalError);
        }

        Ok(())
    }

    #[track_caller]
    /// Handles [`io::Error`]s from I/O operations on kTLS-configured sockets.
    ///
    /// # Overview
    ///
    /// When a socket is configured with kTLS, it can be used like a normal
    /// socket for data transmission - the kernel transparently handles
    /// encryption and decryption. However, TLS control messages (e.g., TLS
    /// alerts) from peers cannot be processed automatically by the kernel,
    /// which returns `EIO` to notify userspace.
    ///
    /// This method helps handle such errors appropriately:
    ///
    /// - **`EIO`**: Attempts to process any received TLS control messages.
    ///   Returns `Ok(())` on success, allowing the caller to retry the
    ///   operation.
    /// - **`Interrupted`**: Indicates the operation was interrupted by a
    ///   signal. Returns `Ok(())`, allowing the caller to retry the operation.
    /// - **`WouldBlock`**: Indicates the operation would block (e.g.,
    ///   non-blocking socket). Returns `Ok(())`, allowing the caller to retry
    ///   the operation.
    /// - **`BrokenPipe`**: Marks the stream as closed.
    /// - Other errors: Aborts the connection with an `internal_error` alert and
    ///   returns the original error.
    ///
    /// # Notes
    ///
    /// Incorrect usage of this method MAY lead to unexpected behavior.
    ///
    /// # Errors
    ///
    /// Returns the original [`io::Error`] if it cannot be recovered from.
    pub fn handle_io_error<S: AsFd>(&mut self, socket: &S, err: io::Error) -> io::Result<()> {
        match err {
            err if err.raw_os_error() == Some(libc::EIO) => {
                crate::trace!("Received EIO, handling TLS control message");

                self.handle_tls_control_message(socket)
                    .map_err(Into::into)
            }
            err if err.kind() == io::ErrorKind::Interrupted => {
                crate::trace!("The I/O operation was interrupted, retrying...");

                Ok(())
            }
            err if err.kind() == io::ErrorKind::WouldBlock => {
                crate::trace!("The I/O operation would block, retrying...");

                Ok(())
            }
            err if err.kind() == io::ErrorKind::BrokenPipe
                || err.kind() == io::ErrorKind::ConnectionReset =>
            {
                crate::trace!("The kTLS offloaded stream is closed ({err})");

                self.state.set_is_read_closed(true);
                self.state.set_is_write_closed(true);

                Err(err)
            }
            _ => {
                crate::trace!(
                    "I/O operation failed, unrecoverable: {err}, try aborting the connection"
                );

                self.send_tls_alert(socket, AlertLevel::Fatal, AlertDescription::InternalError);

                self.state.set_is_read_closed(true);
                self.state.set_is_write_closed(true);

                Err(err)
            }
        }
    }

    #[track_caller]
    #[allow(clippy::too_many_lines)]
    /// Handles TLS control messages received by kernel.
    ///
    /// The caller SHOULD first check if the raw os error returned were
    /// `EIO`, which indicates that there is a TLS control message available.
    ///
    /// But in fact, this method can be called even if there's no TLS control
    /// message (not recommended to do so).
    fn handle_tls_control_message<S: AsFd>(&mut self, socket: &S) -> Result<()> {
        match recv_tls_record(socket.as_fd().as_raw_fd(), &mut self.buffer) {
            Ok(ContentType::Handshake) => {
                return self.handle_tls_control_message_handshake(socket);
            }
            Ok(ContentType::Alert) => {
                if let &[level, desc] = self.buffer.unfilled_initialized() {
                    return self.handle_tls_control_message_alert(
                        socket,
                        AlertLevel::from_int(level),
                        AlertDescription::from_int(desc),
                    );
                }

                // The peer sent an invalid alert. We send back an error
                // and close the connection.

                crate::error!(
                    "Invalid alert message received: {:?}, {:?}",
                    self.buffer.unfilled_initialized(),
                    self.buffer
                );

                return self.abort(
                    socket,
                    InvalidMessage::MessageTooLarge,
                    InvalidMessage::MessageTooLarge.description(),
                );
            }
            Ok(ContentType::ChangeCipherSpec) => {
                // ChangeCipherSpec should only be sent under the following conditions:
                //
                // * TLS 1.2: during a handshake or a rehandshake
                // * TLS 1.3: during a handshake
                //
                // We don't have to worry about handling messages during a handshake
                // and rustls does not support TLS 1.2 rehandshakes so we just emit
                // an error here and abort the connection.

                crate::warn!("Received unexpected ChangeCipherSpec message");

                return self.abort(
                    socket,
                    PeerMisbehaved::IllegalMiddleboxChangeCipherSpec,
                    PeerMisbehaved::IllegalMiddleboxChangeCipherSpec.description(),
                );
            }
            Ok(ContentType::ApplicationData) => {
                // This shouldn't happen in normal operation.

                crate::warn!(
                    "Received {} bytes of application data, unexpected usage",
                    self.buffer.unfilled_initialized().len()
                );

                self.buffer.set_filled_all();
            }
            Ok(_content_type) => {
                crate::error!(
                    "Received unexpected TLS control message: content_type={_content_type:?}",
                );

                return self.abort(
                    socket,
                    InvalidMessage::InvalidContentType,
                    InvalidMessage::InvalidContentType.description(),
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                // No TLS control message available, the caller should retry
                // the I/O operation.

                crate::trace!("No TLS control message available, retrying...");

                return Ok(());
            }
            Err(error) => {
                crate::error!("Failed to receive TLS control message: {error}");

                return self.abort(
                    socket,
                    Error::General(error),
                    AlertDescription::InternalError,
                );
            }
        }

        Ok(())
    }

    #[track_caller]
    #[allow(clippy::too_many_lines)]
    /// Handles a TLS alert received from the peer.
    fn handle_tls_control_message_handshake<S: AsFd>(&mut self, socket: &S) -> Result<()> {
        let mut messages =
            HandshakeMessagesIter::new(self.buffer.unfilled_initialized()).enumerate();

        while let Some((idx, payload)) = messages.next() {
            let Ok((handshake_type, payload)) = payload else {
                return self.abort(
                    socket,
                    InvalidMessage::MessageTooShort,
                    InvalidMessage::MessageTooShort.description(),
                );
            };

            match handshake_type {
                HandshakeType::KeyUpdate
                    if self.session.protocol_version() == ProtocolVersion::TLSv1_3 =>
                {
                    if idx != 0 || messages.next().is_some() {
                        crate::error!(
                            "RFC 8446, section 5.1: Handshake messages MUST NOT span key changes."
                        );

                        return self.abort(
                            socket,
                            PeerMisbehaved::KeyEpochWithPendingFragment,
                            PeerMisbehaved::KeyEpochWithPendingFragment.description(),
                        );
                    }

                    let &[payload] = payload else {
                        crate::error!(
                            "Received invalid KeyUpdate message, expected 1 byte payload, got: \
                             {:?}",
                            payload
                        );

                        return self.abort(
                            socket,
                            InvalidMessage::InvalidKeyUpdate,
                            InvalidMessage::InvalidKeyUpdate.description(),
                        );
                    };

                    let key_update_request = KeyUpdateRequest::from_int(payload);

                    if !matches!(
                        key_update_request,
                        KeyUpdateRequest::UpdateNotRequested | KeyUpdateRequest::UpdateRequested
                    ) {
                        crate::warn!(
                            "Received KeyUpdate message with unknown request value: {payload}"
                        );

                        return self.abort(
                            socket,
                            InvalidMessage::InvalidKeyUpdate,
                            InvalidMessage::InvalidKeyUpdate.description(),
                        );
                    }

                    #[cfg(not(feature = "tls13-key-update"))]
                    {
                        crate::warn!(
                            "Received KeyUpdate [{key_update_request:?}], TLS 1.3 key update \
                             support is disabled"
                        );

                        return self.abort(
                            socket,
                            InvalidMessage::UnexpectedMessage(
                                "TLS 1.3 key update support is disabled",
                            ),
                            AlertDescription::InternalError,
                        );
                    }

                    #[cfg(feature = "tls13-key-update")]
                    {
                        if let Err(error) = self
                            .session
                            .update_rx_secret()
                            .and_then(|secret| secret.set(socket))
                        {
                            crate::error!("Failed to update secret: {error}");

                            return self.abort(socket, error, AlertDescription::InternalError);
                        }

                        match key_update_request {
                            KeyUpdateRequest::UpdateNotRequested => {}
                            KeyUpdateRequest::UpdateRequested => {
                                // Notify the peer that we are updating our TX secret as well.
                                if let Err(error) = send_tls_control_message(
                                    socket.as_fd().as_raw_fd(),
                                    ContentType::Handshake,
                                    &mut [
                                        HandshakeType::KeyUpdate.to_int(), // typ
                                        0,
                                        0,
                                        1, // length
                                        KeyUpdateRequest::UpdateNotRequested.to_int(),
                                    ],
                                )
                                .map_err(Error::KeyUpdateFailed)
                                {
                                    // Failed to notify the peer, abort the connection.
                                    crate::error!("Failed to send KeyUpdate message: {error}");

                                    return self.abort(
                                        socket,
                                        error,
                                        AlertDescription::InternalError,
                                    );
                                }

                                if let Err(error) = self
                                    .session
                                    .update_tx_secret()
                                    .and_then(|secret| secret.set(socket))
                                {
                                    crate::error!("Failed to update TX secret: {error}");

                                    return self.abort(
                                        socket,
                                        error,
                                        AlertDescription::InternalError,
                                    );
                                }
                            }
                            KeyUpdateRequest::Unknown(_) => {
                                unreachable!()
                            }
                        }
                    }
                }
                HandshakeType::NewSessionTicket
                    if self.session.protocol_version() == ProtocolVersion::TLSv1_3 =>
                {
                    if self.session.peer() != Peer::Client {
                        crate::warn!("TLS 1.2 peer sent a TLS 1.3 NewSessionTicket message");

                        return self.abort(
                            socket,
                            InvalidMessage::UnexpectedMessage(
                                "TLS 1.2 peer sent a TLS 1.3 NewSessionTicket message",
                            ),
                            AlertDescription::UnexpectedMessage,
                        );
                    }

                    if let Err(error) = self
                        .session
                        .handle_new_session_ticket(payload)
                    {
                        return self.abort(socket, error, AlertDescription::InternalError);
                    }
                }
                _ if self.session.protocol_version() == ProtocolVersion::TLSv1_3 => {
                    crate::error!(
                        "Unexpected handshake message for a TLS 1.3 connection: \
                         typ={handshake_type:?}",
                    );

                    return self.abort(
                        socket,
                        InvalidMessage::UnexpectedMessage(
                            "expected KeyUpdate or NewSessionTicket message",
                        ),
                        AlertDescription::UnexpectedMessage,
                    );
                }
                _ => {
                    crate::error!(
                        "Unexpected handshake message: ver={:?}, typ={handshake_type:?}",
                        self.session.protocol_version()
                    );

                    return self.abort(
                        socket,
                        InvalidMessage::UnexpectedMessage(
                            "handshake messages are not expected on TLS 1.2 connections",
                        ),
                        AlertDescription::UnexpectedMessage,
                    );
                }
            }
        }

        Ok(())
    }

    #[track_caller]
    /// Handles a TLS alert received from the peer.
    fn handle_tls_control_message_alert<S: AsFd>(
        &mut self,
        socket: &S,
        level: AlertLevel,
        desc: AlertDescription,
    ) -> Result<()> {
        match desc {
            AlertDescription::CloseNotify
                if self.session.protocol_version() == ProtocolVersion::TLSv1_2 =>
            {
                // RFC 5246, section 7.2.1: Unless some other fatal alert has been transmitted,
                // each party is required to send a close_notify alert before closing the write
                // side of the connection.  The other party MUST respond with a close_notify
                // alert of its own and close down the connection immediately, discarding any
                // pending writes.
                crate::trace!("Received `close_notify` alert, should shutdown the TLS stream");

                self.shutdown(socket);
            }
            AlertDescription::CloseNotify => {
                // RFC 8446, section 6.1: Each party MUST send a "close_notify" alert before
                // closing its write side of the connection, unless it has already sent some
                // error alert. This does not have any effect on its read side of the
                // connection. Note that this is a change from versions of TLS prior to TLS 1.3
                // in which implementations were required to react to a "close_notify" by
                // discarding pending writes and sending an immediate "close_notify" alert of
                // their own. That previous requirement could cause truncation in the read
                // side. Both parties need not wait to receive a "close_notify" alert before
                // closing their read side of the connection, though doing so would introduce
                // the possibility of truncation.

                crate::trace!(
                    "Received `close_notify` alert, should shutdown the read side of TLS stream"
                );

                self.state.set_is_read_closed(true);
            }
            _ if self.session.protocol_version() == ProtocolVersion::TLSv1_2
                && level == AlertLevel::Warning =>
            {
                // RFC 5246, section 7.2.2: If an alert with a level of warning
                // is sent and received, generally the connection can continue
                // normally.

                crate::warn!("Received non fatal alert, level={level:?}, desc: {desc:?}");
            }
            _ => {
                // All other alerts are treated as fatal and result in us immediately shutting
                // down the connection and emitting an error.

                crate::error!("Received fatal alert, desc: {desc:?}");

                self.state.set_is_read_closed(true);
                self.state.set_is_write_closed(true);

                return Err(Error::AlertReceived(desc));
            }
        }

        Ok(())
    }

    #[track_caller]
    /// Closes the read side of the kTLS connection and sends a `close_notify`
    /// alert to the peer.
    pub fn shutdown<S: AsFd>(&mut self, socket: &S) {
        crate::trace!("Shutting down the TLS stream with `close_notify` alert...");

        self.send_tls_alert(socket, AlertLevel::Warning, AlertDescription::CloseNotify);

        if self.session.protocol_version() == ProtocolVersion::TLSv1_2 {
            // See RFC 5246, section 7.2.1
            self.state.set_is_read_closed(true);
        }

        self.state.set_is_write_closed(true);
    }

    #[track_caller]
    /// Aborts the kTLS connection and sends a fatal alert to the peer.
    fn abort<T, S, E, D>(&mut self, socket: &S, error: E, description: D) -> Result<T>
    where
        S: AsFd,
        E: Into<Error>,
        D: Into<AlertDescription>,
    {
        crate::trace!("Aborting the TLS stream with fatal alert...");

        self.send_tls_alert(socket, AlertLevel::Fatal, description.into());

        self.state.set_is_read_closed(true);
        self.state.set_is_write_closed(true);

        Err(error.into())
    }

    #[track_caller]
    /// Sends a TLS alert to the peer.
    fn send_tls_alert<S: AsFd>(
        &mut self,
        socket: &S,
        level: AlertLevel,
        description: AlertDescription,
    ) {
        if !self.state.is_write_closed() {
            let _ = send_tls_control_message(
                socket.as_fd().as_raw_fd(),
                ContentType::Alert,
                &mut [level.to_int(), description.to_int()],
            )
            .inspect_err(|_e| {
                crate::trace!("Failed to send alert: {_e}");
            });
        }
    }
}

#[bitfield(u8)]
/// State of the kTLS connection.
pub struct State {
    /// Whether the read side is closed.
    pub is_read_closed: bool,

    /// Whether the write side is closed.
    pub is_write_closed: bool,

    #[bits(6)]
    _reserved: u8,
}

impl State {
    #[inline]
    #[must_use]
    /// Returns whether the connection is fully closed (both read and write
    /// sides).
    pub const fn is_closed(&self) -> bool {
        self.is_read_closed() && self.is_write_closed()
    }
}

struct HandshakeMessagesIter<'a> {
    inner: Result<Option<&'a [u8]>, ()>,
}

impl<'a> HandshakeMessagesIter<'a> {
    #[inline]
    const fn new(payloads: &'a [u8]) -> Self {
        Self {
            inner: Ok(Some(payloads)),
        }
    }
}

impl<'a> Iterator for HandshakeMessagesIter<'a> {
    type Item = Result<(HandshakeType, &'a [u8]), ()>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        match self.inner {
            Ok(None) => None,
            Ok(Some(&[typ, a, b, c, ref rest @ ..])) => {
                let handshake_type = HandshakeType::from_int(typ);
                let payload_length = u32::from_be_bytes([0, a, b, c]) as usize;

                let Some((payload, rest)) = rest.split_at_checked(payload_length) else {
                    crate::error!(
                        "Received truncated handshake message payload, expected: \
                         {payload_length}, actual: {}",
                        rest.len()
                    );

                    self.inner = Err(());

                    return Some(Err(()));
                };

                if rest.is_empty() {
                    self.inner = Ok(None);
                } else {
                    self.inner = Ok(Some(rest));
                }

                Some(Ok((handshake_type, payload)))
            }
            Ok(Some(_truncated)) => {
                crate::error!("Received truncated handshake message payload: {_truncated:?}");

                self.inner = Err(());

                Some(Err(()))
            }
            Err(()) => Some(Err(())),
        }
    }
}
