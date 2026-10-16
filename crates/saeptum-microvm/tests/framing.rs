// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Line framing and Firecracker's hybrid-vsock handshake.
//!
//! Positive: the connect command and the acknowledgement are Firecracker's
//! (`docs/vsock.md`, v1.17.0), and a line is read without consuming what
//! follows it. Negative: a malformed acknowledgement, a line past its bound,
//! text that is not UTF-8 and a silent peer are each refused -- the last at
//! its deadline, over a real socket pair. Boundary: a line of exactly the
//! bound is read and a peer that closes early is reported, not failed.

mod common;

use std::io::{Cursor, Read};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use saeptum_microvm::{
    MAX_ACK_BYTES, MicroVmError, Unframed, connect_command, deadline_error, parse_ack, read_line,
    timed_out,
};

use common::{Fallible, PORT};

/// A budget the tests never approach.
const AMPLE: Duration = Duration::from_secs(5);

// --- Positive -------------------------------------------------------------

/// Positive: the handshake is Firecracker's text protocol.
#[test]
fn the_handshake_is_firecrackers() -> Fallible {
    assert_eq!(connect_command(PORT), "CONNECT 5210\n");
    assert_eq!(parse_ack("OK 1073741825\n")?, 1_073_741_825);
    Ok(())
}

/// Positive: one line is read and the next byte is left in the stream.
#[test]
fn a_line_is_read_and_nothing_after_it() -> Fallible {
    let mut stream = Cursor::new(b"OK 7\nrest".to_vec());
    let line = read_line(&mut stream, MAX_ACK_BYTES, AMPLE, "a test line")?;
    assert_eq!(line, Ok("OK 7\n".to_owned()));
    let mut rest = String::new();
    stream.read_to_string(&mut rest)?;
    assert_eq!(rest, "rest");
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: anything but `OK <decimal>\n` is not an acknowledgement.
#[test]
fn a_malformed_acknowledgement_is_refused() {
    for line in [
        "OK\n",
        "OK \n",
        "NO 1\n",
        "OK 12",
        "OK -1\n",
        "OK 99999999999\n",
        "ok 1\n",
    ] {
        assert!(
            matches!(parse_ack(line), Err(MicroVmError::Protocol(_))),
            "{line:?}"
        );
    }
}

/// Negative: a line past its bound, and text that is not UTF-8, are refused.
#[test]
fn an_unbounded_or_foreign_line_is_refused() {
    let mut long = Cursor::new(vec![b'x'; 64]);
    assert!(matches!(
        read_line(&mut long, 16, AMPLE, "a test line"),
        Err(MicroVmError::Protocol(_))
    ));
    let mut foreign = Cursor::new(vec![0xff, 0xfe, b'\n']);
    assert!(matches!(
        read_line(&mut foreign, 16, AMPLE, "a test line"),
        Err(MicroVmError::Protocol(_))
    ));
}

/// Negative: a peer that never writes is a deadline error, not a hang.
#[test]
fn a_silent_peer_misses_the_deadline() -> Fallible {
    let (mut near, _far) = UnixStream::pair()?;
    near.set_read_timeout(Some(Duration::from_millis(50)))?;
    let outcome = read_line(&mut near, MAX_ACK_BYTES, AMPLE, "the vsock handshake");
    assert!(matches!(
        outcome,
        Err(MicroVmError::Deadline {
            what: "the vsock handshake",
            ..
        })
    ));
    let error = std::io::Error::from(std::io::ErrorKind::WouldBlock);
    assert!(timed_out(&error));
    assert!(!timed_out(&std::io::Error::from(
        std::io::ErrorKind::BrokenPipe
    )));
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a line of exactly the bound is read.
#[test]
fn a_line_of_exactly_the_bound_is_read() -> Fallible {
    let mut exact = Cursor::new(b"OK 1234567890123456789012345678\n".to_vec());
    let line = read_line(&mut exact, MAX_ACK_BYTES, AMPLE, "a test line")?;
    assert_eq!(line.map(|text| text.len()), Ok(MAX_ACK_BYTES));
    Ok(())
}

/// Boundary: a peer that closes before its newline is reported with the
/// byte count, so a caller polling for a listener can tell "not yet".
#[test]
fn an_early_close_is_reported() -> Fallible {
    let (mut near, far) = UnixStream::pair()?;
    drop(far);
    assert_eq!(
        read_line(&mut near, MAX_ACK_BYTES, AMPLE, "a test line")?,
        Err(Unframed::Closed(0))
    );
    let mut partial = Cursor::new(b"OK".to_vec());
    assert_eq!(
        read_line(&mut partial, MAX_ACK_BYTES, AMPLE, "a test line")?,
        Err(Unframed::Closed(2))
    );
    let deadline = deadline_error("a test", Duration::from_millis(1500));
    assert_eq!(deadline.to_string(), "a test missed its 1500 ms deadline");
    Ok(())
}
