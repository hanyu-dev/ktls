//! Safe syscall wrappers.
//!
//! This module is not meant to be used directly.

// Since Rust 2021 doesn't have `size_of_val` included in prelude.
#![allow(unused_qualifications)]
#![allow(unsafe_code)]
#![allow(trivial_numeric_casts)]
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_possible_wrap)]
#![allow(clippy::cast_sign_loss)]

use std::os::fd::RawFd;
use std::{io, mem, ptr};

use crate::tls::ContentType;
use crate::utils::Buffer;

#[repr(C)]
union CmsgBuf<const CMSG_BUF_SIZE: usize> {
    cmsghdr: libc::cmsghdr,
    _buf: [u8; CMSG_BUF_SIZE],
}

/// A safe wrapper around [`libc::sendmsg`] sending a TLS control message.
///
/// # Arguments
///
/// - `socket`: The file descriptor to send the message to.
/// - `content_type`: The TLS content type.
/// - `payload`: The payload to send.
///
/// # Returns
///
/// The number of bytes sent.
///
/// # Errors
///
/// * Syscall error.
pub fn send_tls_control_message(
    socket: RawFd,
    content_type: ContentType,
    payload: &mut [u8],
) -> io::Result<usize> {
    // SAFETY: zeroed is fine for msghdr as we will set all the fields we use.
    let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };

    let mut cmsg_buf: CmsgBuf<{ cmsg_space::<[u8; 1]>() }> = unsafe { mem::zeroed() };

    cmsg_buf.cmsghdr.cmsg_type = libc::TLS_SET_RECORD_TYPE;
    cmsg_buf.cmsghdr.cmsg_level = libc::SOL_TLS;
    cmsg_buf.cmsghdr.cmsg_len = mem::size_of_val(&cmsg_buf) as _;

    unsafe {
        libc::CMSG_DATA(&raw const cmsg_buf.cmsghdr).write_unaligned(content_type.to_int());
    };

    msghdr.msg_control = ptr::from_mut(&mut cmsg_buf).cast();
    msghdr.msg_controllen = mem::size_of_val(&cmsg_buf) as _;

    let iovec = &mut libc::iovec {
        iov_base: ptr::from_mut(payload).cast(),
        iov_len: payload.len() as _,
    };

    msghdr.msg_iov = ptr::from_mut(iovec).cast();
    msghdr.msg_iovlen = 1;

    // SAFETY: syscall
    let ret = unsafe { libc::sendmsg(socket, &raw const msghdr, 0) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(ret as usize)
}

/// A safe wrapper around [`libc::recvmsg`] receiving TLS record payloads.
///
/// # Arguments
///
/// - `fd`: The file descriptor to receive the message from.
/// - `buffer`: The buffer to receive the message into.
///
/// # Returns
///
/// The [`ContentType`] and the number of bytes read into the buffer.
///
/// # Notes
///
/// This only reads the TLS message payload into the given buffer, i.e., not
/// including the `msg_type` or `length` fields.
///
/// # Errors
///
/// * Syscall error.
/// * Rare bugs (e.g., no control message received).
pub fn recv_tls_record(socket: RawFd, buffer: &mut Buffer) -> io::Result<ContentType> {
    let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };

    let mut cmsg_buf: CmsgBuf<{ cmsg_space::<[u8; 1]>() }> = unsafe { mem::zeroed() };

    // FIXME: For Linux kernel <= 5.10, will read more cmsgs than one (?).
    msghdr.msg_control = ptr::from_mut(&mut cmsg_buf).cast();
    msghdr.msg_controllen = mem::size_of_val(&cmsg_buf) as _;

    let spare = {
        buffer.reserve(u16::MAX as usize + 5);
        buffer.unfilled_mut()
    };
    let iovec = &mut libc::iovec {
        iov_base: ptr::from_mut(spare).cast(),
        iov_len: spare.len() as _,
    };

    msghdr.msg_iov = ptr::from_mut(iovec).cast();
    msghdr.msg_iovlen = 1;

    // SAFETY: syscall
    let ret = unsafe { libc::recvmsg(socket, &raw mut msghdr, 0) };

    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    let cmsghdr = {
        let ptr = if msghdr.msg_controllen > 0 {
            debug_assert!(!msghdr.msg_control.is_null());
            debug_assert!(cmsg_space::<[u8; 1]>() >= msghdr.msg_controllen as _);

            unsafe { libc::CMSG_FIRSTHDR(&raw const msghdr) }
        } else {
            ptr::null()
        };

        // SAFETY: we checked the pointer above.
        unsafe { ptr.as_ref() }
    };

    if msghdr.msg_flags & libc::MSG_CTRUNC == libc::MSG_CTRUNC {
        // Rare bug: the buffer is not enough to hold the control message.
        return Err(io::Error::from_raw_os_error(libc::ENOBUFS));
    }

    let Some(cmsghdr) = cmsghdr else {
        return Err(io::Error::other("rare bug: no control message received"));
    };

    match (cmsghdr.cmsg_level, cmsghdr.cmsg_type) {
        (libc::SOL_TLS, libc::TLS_GET_RECORD_TYPE) => {}
        (cmsg_level, cmsg_type) => {
            return Err(io::Error::other(format!(
                "unexpected cmsg: cmsg_level={cmsg_level}, cmsg_type={cmsg_type}",
            )));
        }
    }

    // SAFETY: syscall; we checked the pointer above.
    let Some(content_type) = unsafe { libc::CMSG_DATA(cmsghdr).as_ref() }
        .copied()
        .map(ContentType::from_int)
    else {
        return Err(io::Error::other(
            "rare bug: no data in control message received",
        ));
    };

    // SAFETY: we just wrote valid `ret` bytes into the buffer.
    unsafe { buffer.assume_init_additional(ret as usize) };

    Ok(content_type)
}

const fn cmsg_space<T>() -> usize {
    // SAFETY: CMSG_SPACE is always safe
    unsafe { libc::CMSG_SPACE(mem::size_of::<T>() as libc::c_uint) as usize }
}
