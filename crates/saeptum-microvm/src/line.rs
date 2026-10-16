// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Newline-framed text under a byte bound and a deadline, and Firecracker's
//! hybrid-vsock handshake.
//!
//! Firecracker mediates between `AF_UNIX` on the host and `AF_VSOCK` in the
//! guest (its `docs/vsock.md`, v1.17.0): a host connects to the device's Unix
//! socket, sends `CONNECT <port>\n`, and reads `OK <host port>\n` once a guest
//! listener on that port has accepted; with no listener, Firecracker closes
//! the connection. Everything after the acknowledgement is the guest's own
//! stream. Both sides here frame one message per line.
//!
//! Every read is byte-at-a-time, so nothing past the newline is consumed, and
//! every loop is bounded by the byte bound; the deadline is the socket's own
//! read timeout plus a wall-clock check between bytes (HISS-02).

use std::io::{ErrorKind, Read};
use std::time::{Duration, Instant};

use crate::error::MicroVmError;

/// Scalar upper bound, in bytes, on the handshake acknowledgement.
pub const MAX_ACK_BYTES: usize = 32;

/// Returns the connect command for guest port `port`.
#[must_use]
pub fn connect_command(port: u32) -> String {
    format!("CONNECT {port}\n")
}

/// Parses Firecracker's acknowledgement, returning the host-side port.
///
/// # Errors
///
/// Returns [`MicroVmError::Protocol`] for anything but `OK <decimal>\n`.
pub fn parse_ack(line: &str) -> Result<u32, MicroVmError> {
    line.strip_suffix('\n')
        .and_then(|body| body.strip_prefix("OK "))
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|port| port.parse::<u32>().ok())
        .ok_or_else(|| MicroVmError::Protocol(format!("the handshake answered {line:?}")))
}

/// How a framed read ended without a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Unframed {
    /// The peer closed the stream before a newline; `usize` bytes had arrived.
    Closed(usize),
}

/// Reads one newline-terminated line of at most `bound` bytes within `budget`.
///
/// Returns `Ok(Err(Unframed::Closed(n)))` when the peer closed first, which a
/// caller polling for a listener treats as "not yet" rather than a failure.
/// `budget` is checked between bytes; a blocking read is bounded by the
/// reader's own timeout, which the callers set no longer than `budget`.
///
/// # Errors
///
/// Returns [`MicroVmError::Protocol`] past `bound` or for text that is not
/// UTF-8, [`MicroVmError::Deadline`] when the reader's timeout or `budget`
/// passes, and [`MicroVmError::Io`] for any other read failure.
pub fn read_line<R: Read>(
    reader: &mut R,
    bound: usize,
    budget: Duration,
    what: &'static str,
) -> Result<Result<String, Unframed>, MicroVmError> {
    let started = Instant::now();
    let mut bytes = Vec::with_capacity(bound);
    let mut byte = [0_u8; 1];
    for _ in 0..bound {
        if started.elapsed() > budget {
            return Err(deadline_error(what, budget));
        }
        match reader.read(&mut byte) {
            Ok(0) => return Ok(Err(Unframed::Closed(bytes.len()))),
            Ok(_) => bytes.extend_from_slice(&byte),
            Err(error) if timed_out(&error) => return Err(deadline_error(what, budget)),
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(MicroVmError::io(what, error)),
        }
        if bytes.last() == Some(&b'\n') {
            let text = String::from_utf8(bytes).map_err(|_| {
                MicroVmError::Protocol(format!("{what} carried text that is not UTF-8"))
            })?;
            return Ok(Ok(text));
        }
    }
    Err(MicroVmError::Protocol(format!(
        "{what} passed its bound of {bound} bytes without a newline"
    )))
}

/// Returns `true` for the error kinds a socket read timeout yields.
#[must_use]
pub fn timed_out(error: &std::io::Error) -> bool {
    matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut)
}

/// Builds the deadline error for `what`, naming its budget.
#[must_use]
pub const fn deadline_error(what: &'static str, budget: Duration) -> MicroVmError {
    MicroVmError::Deadline {
        what,
        millis: budget.as_millis(),
    }
}
