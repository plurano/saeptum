// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The guest's framing of one request and one answer.
//!
//! [`serve`](saeptum_microvm::serve) needs `AF_VSOCK` inside a microVM and is
//! not run here; [`answer`] is what it runs per connection, over any stream.
//!
//! Positive: an answer line is written and the guest's context identifier
//! reaches the responder. Negative: a refusal, and an answer carrying its own
//! newline, become one `ERROR` line; a request past its bound, one that is not
//! UTF-8 and one cut short are refused. Boundary: a request of exactly its
//! bound is answered.

mod common;

use std::io::Cursor;

use saeptum_microvm::{MicroVmError, Responder, Service, answer};

use common::{FIRST_CID, Fallible, PORT};

/// Runs [`answer`] on `request` and returns what was written.
fn written<R: Responder>(
    request: &[u8],
    bound: usize,
    responder: &mut R,
) -> Result<String, MicroVmError> {
    let mut reader = Cursor::new(request.to_vec());
    let mut writer = Vec::new();
    answer(&mut reader, &mut writer, FIRST_CID, bound, responder)?;
    String::from_utf8(writer).map_err(|_| MicroVmError::Protocol("not UTF-8".to_owned()))
}

/// Answers with the request in upper case and the context identifier.
#[expect(
    clippy::unnecessary_wraps,
    reason = "a responder returns a Result; this one never refuses"
)]
fn shout(request: &str, cid: u32) -> Result<String, String> {
    Ok(format!("{} {cid}", request.to_uppercase()))
}

// --- Positive -------------------------------------------------------------

/// Positive: the answer is one line and carries the context identifier.
#[test]
fn an_answer_line_is_written() -> Fallible {
    let text = written(b"evaluate\n", 64, &mut shout)?;
    assert_eq!(text, format!("EVALUATE {FIRST_CID}\n"));
    let service = Service {
        port: PORT,
        max_request_bytes: 64,
    };
    assert_eq!(service.port, 5210);
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a refusal is folded onto one `ERROR` line.
#[test]
fn a_refusal_is_one_error_line() -> Fallible {
    let mut refuse = |_: &str, _: u32| -> Result<String, String> { Err("bad\nrequest".to_owned()) };
    assert_eq!(written(b"x\n", 64, &mut refuse)?, "ERROR bad request\n");
    let mut leak = |_: &str, _: u32| -> Result<String, String> { Ok("one\ntwo".to_owned()) };
    assert_eq!(
        written(b"x\n", 64, &mut leak)?,
        "ERROR the answer carried a newline of its own\n"
    );
    Ok(())
}

/// Negative: an over-long, foreign or cut-short request is refused.
#[test]
fn a_malformed_request_is_refused() {
    for request in [&b"0123456789abcdef\n"[..], &[0xff, 0xfe, b'\n'], b"cut"] {
        assert!(
            matches!(
                written(request, 16, &mut shout),
                Err(MicroVmError::Protocol(_))
            ),
            "{request:?}"
        );
    }
}

// --- Boundary -------------------------------------------------------------

/// Boundary: a request of exactly its bound, newline included, is answered.
#[test]
fn a_request_of_exactly_its_bound_is_answered() -> Fallible {
    let request = format!("{}\n", "a".repeat(15));
    let text = written(request.as_bytes(), 16, &mut shout)?;
    assert_eq!(text, format!("{} {FIRST_CID}\n", "A".repeat(15)));
    Ok(())
}
