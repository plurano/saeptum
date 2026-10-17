// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The guest side: a bounded line service on `AF_VSOCK`, run as the
//! microVM's init.
//!
//! [`serve`] listens on the caller's port for any local context, answers at
//! most [`MAX_GUEST_CONNECTIONS`] connections with one line each, and
//! returns when that bound is reached or no connection arrives within
//! [`ACCEPT_BUDGET`]. Every socket carries a read and a write timeout
//! (HISS-02), and `accept` honours the listener's.
//!
//! What a request means is the caller's: a [`Responder`] turns one request
//! line and the guest's own context identifier into one answer line.
//! [`answer`] frames it, and a responder's refusal is answered with one
//! `ERROR <reason>` line rather than silence, so the host reports the
//! guest's reason ([`crate::vm::RunningVm::exchange`]).
//!
//! [`signal_boot_complete`] tells Firecracker's boot timer that the guest
//! has booted, so the host log carries its boot time.

use std::fmt::Display;
use std::io::{Read, Write};
use std::time::Duration;

use socket2::{Domain, SockAddr, Socket, Type};

use crate::error::MicroVmError;
use crate::line::{Unframed, read_line, timed_out};

mod boot;

pub use boot::{BOOT_COMPLETE_MAGIC, BOOT_TIMER_ADDRESS, DEV_MEM, signal_boot_complete};

/// Scalar upper bound on the connections one guest answers.
pub const MAX_GUEST_CONNECTIONS: u32 = 16;

/// How long the guest waits for the next connection before it ends.
pub const ACCEPT_BUDGET: Duration = Duration::from_secs(120);

/// How long one request and its answer may take inside the guest.
pub const GUEST_EXCHANGE_BUDGET: Duration = Duration::from_secs(5);

/// `VMADDR_CID_ANY`: listen whatever this guest's context identifier is.
pub const VMADDR_CID_ANY: u32 = u32::MAX;

/// The listen backlog.
pub const BACKLOG: i32 = 4;

/// Turns one request line (newline stripped) and the guest's context
/// identifier into one answer line (no newline), or a refusal.
pub trait Responder {
    /// Why a request was refused; written after `ERROR `.
    type Refusal: Display;

    /// Answers one request.
    ///
    /// # Errors
    ///
    /// Returns the refusal the host will read as `ERROR <reason>`.
    fn respond(&mut self, request: &str, cid: u32) -> Result<String, Self::Refusal>;
}

impl<F, E> Responder for F
where
    F: FnMut(&str, u32) -> Result<String, E>,
    E: Display,
{
    type Refusal = E;

    fn respond(&mut self, request: &str, cid: u32) -> Result<String, E> {
        self(request, cid)
    }
}

/// What the guest service listens on and accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Service {
    /// The `AF_VSOCK` port.
    pub port: u32,
    /// The bound on one request line, its newline included.
    pub max_request_bytes: usize,
}

/// Binds `service.port` and answers until the bound or the budget.
///
/// Returns how many connections were answered. A connection that fails is
/// logged to `log` and counted; it does not end the service.
///
/// # Errors
///
/// Returns [`MicroVmError::Io`] when the socket cannot be created, bound or
/// listened on, or `accept` fails for a reason other than its timeout.
pub fn serve<R: Responder>(
    service: Service,
    log: &mut dyn Write,
    responder: &mut R,
) -> Result<u32, MicroVmError> {
    let listener = Socket::new(Domain::VSOCK, Type::STREAM, None)
        .map_err(|error| MicroVmError::io("creating the AF_VSOCK socket", error))?;
    listener
        .bind(&SockAddr::vsock(VMADDR_CID_ANY, service.port))
        .and_then(|()| listener.listen(BACKLOG))
        .and_then(|()| listener.set_read_timeout(Some(ACCEPT_BUDGET)))
        .map_err(|error| MicroVmError::io("listening on the AF_VSOCK port", error))?;
    let _ = writeln!(log, "guest: listening on vsock port {}", service.port);
    accept_loop(&listener, service, log, responder)
}

/// Answers on `listener`, which already listens and carries its accept
/// timeout, until [`MAX_GUEST_CONNECTIONS`] or that timeout.
///
/// [`serve`] calls it on its `AF_VSOCK` listener; the tests below call it on
/// a Unix-domain one, which a host without a guest can create.
pub(crate) fn accept_loop<R: Responder>(
    listener: &Socket,
    service: Service,
    log: &mut dyn Write,
    responder: &mut R,
) -> Result<u32, MicroVmError> {
    let mut served = 0_u32;
    for _ in 0..MAX_GUEST_CONNECTIONS {
        match listener.accept() {
            Ok((connection, _peer)) => {
                if let Err(error) = handle(&connection, service, responder) {
                    let _ = writeln!(log, "guest: {error}");
                }
                served = served.saturating_add(1);
            }
            Err(error) if timed_out(&error) => break,
            Err(error) => return Err(MicroVmError::io("accepting on the AF_VSOCK port", error)),
        }
    }
    Ok(served)
}

/// Answers one accepted `AF_VSOCK` connection.
fn handle<R: Responder>(
    connection: &Socket,
    service: Service,
    responder: &mut R,
) -> Result<(), MicroVmError> {
    connection
        .set_read_timeout(Some(GUEST_EXCHANGE_BUDGET))
        .and_then(|()| connection.set_write_timeout(Some(GUEST_EXCHANGE_BUDGET)))
        .map_err(|error| MicroVmError::io("setting a socket timeout", error))?;
    let local = connection
        .local_addr()
        .map_err(|error| MicroVmError::io("reading the local vsock address", error))?;
    let (cid, _port) = local
        .as_vsock_address()
        .ok_or_else(|| MicroVmError::Protocol("the local address is not AF_VSOCK".to_owned()))?;
    let mut reader = connection;
    let mut writer = connection;
    answer(
        &mut reader,
        &mut writer,
        cid,
        service.max_request_bytes,
        responder,
    )
}

/// Reads one request line from `reader`, asks `responder`, and writes one
/// answer line to `writer`.
///
/// A refusal, or an answer that carries a newline of its own, is written as
/// `ERROR <reason>`. The reader's own timeout bounds each blocking read; the
/// whole read is also bounded by [`GUEST_EXCHANGE_BUDGET`].
///
/// # Errors
///
/// Returns [`MicroVmError`] when the request passes `max_request_bytes` or
/// its deadline, is not UTF-8, the host closes before its newline, or the
/// answer cannot be written.
pub fn answer<In: Read, Out: Write, R: Responder>(
    reader: &mut In,
    writer: &mut Out,
    cid: u32,
    max_request_bytes: usize,
    responder: &mut R,
) -> Result<(), MicroVmError> {
    let line = match read_line(
        reader,
        max_request_bytes,
        GUEST_EXCHANGE_BUDGET,
        "the request",
    )? {
        Ok(line) => line,
        Err(Unframed::Closed(bytes)) => {
            return Err(MicroVmError::Protocol(format!(
                "the host closed the stream after {bytes} bytes of its request"
            )));
        }
    };
    let reply = match responder.respond(line.trim_end_matches('\n'), cid) {
        Ok(body) if body.contains('\n') => {
            "ERROR the answer carried a newline of its own\n".to_owned()
        }
        Ok(body) => format!("{body}\n"),
        Err(refusal) => format!("ERROR {}\n", single_line(&refusal.to_string())),
    };
    writer
        .write_all(reply.as_bytes())
        .map_err(|error| MicroVmError::io("sending the answer", error))
}

/// Folds a refusal onto one line, so it cannot break the framing.
fn single_line(text: &str) -> String {
    text.replace('\n', " ")
}

#[cfg(test)]
mod tests {
    //! The accept loop on a Unix-domain listener: a host without a guest
    //! reaches every arm of it this way.

    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::time::Duration;

    use socket2::{Domain, SockAddr, Socket, Type};

    use super::{Service, accept_loop};
    use crate::error::MicroVmError;

    type Fallible = Result<(), Box<dyn std::error::Error>>;

    const SERVICE: Service = Service {
        port: 5_000,
        max_request_bytes: 64,
    };

    /// A fresh socket path for `name`, unique to this process.
    fn socket_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("saeptum-guest-{name}-{}.sock", std::process::id()))
    }

    /// A Unix-domain listener on `path` whose accept times out after
    /// `timeout`.
    fn listener(path: &PathBuf, timeout: Duration) -> Result<Socket, std::io::Error> {
        let _ = std::fs::remove_file(path);
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(path)?)?;
        socket.listen(1)?;
        socket.set_read_timeout(Some(timeout))?;
        Ok(socket)
    }

    /// Answers a request in upper case and refuses an empty one.
    fn shout(request: &str, _cid: u32) -> Result<String, String> {
        if request.is_empty() {
            return Err("empty request".to_owned());
        }
        Ok(request.to_uppercase())
    }

    /// Positive: no connection within the accept timeout ends the service
    /// with nothing served, not with an error.
    #[test]
    fn an_accept_timeout_ends_the_service() -> Fallible {
        let path = socket_path("idle");
        let socket = listener(&path, Duration::from_millis(50))?;
        let mut log = Vec::new();
        let served = accept_loop(&socket, SERVICE, &mut log, &mut shout);
        std::fs::remove_file(&path)?;
        assert!(matches!(served, Ok(0)), "{served:?}");
        Ok(())
    }

    /// Negative: an accept that fails for a reason other than its timeout
    /// (a socket that never listened) is an I/O error.
    #[test]
    fn a_failing_accept_is_an_io_error() -> Fallible {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        let mut log = Vec::new();
        let served = accept_loop(&socket, SERVICE, &mut log, &mut shout);
        assert!(
            matches!(
                served,
                Err(MicroVmError::Io {
                    what: "accepting on the AF_VSOCK port",
                    ..
                })
            ),
            "{served:?}"
        );
        Ok(())
    }

    /// Negative: a connection that cannot be answered is logged and counted,
    /// and does not end the service.
    #[test]
    fn a_failed_connection_is_logged_and_counted() -> Fallible {
        let path = socket_path("non-vsock");
        let socket = listener(&path, Duration::from_millis(500))?;
        let mut client = UnixStream::connect(&path)?;
        client.set_write_timeout(Some(Duration::from_secs(1)))?;
        client.write_all(b"ping\n")?;
        let mut log = Vec::new();
        let served = accept_loop(&socket, SERVICE, &mut log, &mut shout);
        std::fs::remove_file(&path)?;
        assert!(matches!(served, Ok(1)), "{served:?}");
        let logged = String::from_utf8(log)?;
        assert!(
            logged.contains("guest: ") && logged.contains("not AF_VSOCK"),
            "{logged}"
        );
        Ok(())
    }
}
