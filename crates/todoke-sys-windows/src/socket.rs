//! Socket options the portable socket crates do not expose.
//!
//! `SO_EXCLUSIVEADDRUSE` makes a listener's port its own: no other socket
//! may bind the port beside it, whatever its own options, and binding
//! fails if another socket already holds any part of the port (another
//! address family, a wildcard, a specific address). Without it Windows
//! lets sockets share a port in ways that hand some connections to the
//! other program.
//!
//! The only unsafe code is the one Winsock call below.

#![allow(unsafe_code, reason = "one Winsock setsockopt call, justified below")]

use std::io;
use std::os::windows::io::AsRawSocket;

use windows_sys::Win32::Networking::WinSock::{
    SO_EXCLUSIVEADDRUSE, SOCKET, SOL_SOCKET, WSAGetLastError, setsockopt,
};

/// Sets `SO_EXCLUSIVEADDRUSE` on `socket`, before it is bound.
///
/// # Errors
///
/// The Winsock error.
pub fn exclusive_address_use(socket: &impl AsRawSocket) -> io::Result<()> {
    let on: i32 = 1;
    let length = i32::try_from(size_of::<i32>()).unwrap_or(4);
    let handle = SOCKET::try_from(socket.as_raw_socket())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: `socket` is a live socket handle borrowed for the call; the
    // option value points at `on`, an i32 that outlives the call, and
    // `length` is its size.
    let status = unsafe {
        setsockopt(
            handle,
            SOL_SOCKET,
            SO_EXCLUSIVEADDRUSE,
            (&raw const on).cast(),
            length,
        )
    };
    if status == 0 {
        Ok(())
    } else {
        // SAFETY: no preconditions; reads this thread's last Winsock error.
        Err(io::Error::from_raw_os_error(unsafe { WSAGetLastError() }))
    }
}
