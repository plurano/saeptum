// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! REQ-P10-04: the submission-queue bound.
//!
//! Positive: a batch inside the depth is accounted for. Negative: a batch past
//! the depth is refused and changes nothing. Boundary: exactly the queue depth
//! is admitted and one more is not.
//!
//! There is no `io_uring` here. A pass is evidence about a bound.

mod common;

use saeptum_capsule::{IOURING_QUEUE_DEPTH, RingCore, SandboxError};

use common::Fallible;

// --- Positive -------------------------------------------------------------

/// Positive: submissions accumulate and the ring drains.
#[test]
fn submissions_accumulate_and_drain() -> Fallible {
    let mut core = RingCore::new(0);
    assert_eq!(core.core_id(), 0);
    assert!(core.is_drained());
    assert_eq!(core.submit(4)?, 4);
    assert_eq!(core.submit(8)?, 8);
    assert_eq!(core.submitted(), 12);
    assert_eq!(core.completed(), 12);
    assert!(core.is_drained());
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a batch past the queue depth is refused and nothing is counted.
#[test]
fn a_batch_past_the_queue_depth_is_refused() -> Fallible {
    let mut core = RingCore::new(3);
    core.submit(16)?;
    let refused = core.submit(IOURING_QUEUE_DEPTH.saturating_add(1));
    assert_eq!(
        refused,
        Err(SandboxError::BatchOverQueueDepth {
            entries: 1_025,
            depth: IOURING_QUEUE_DEPTH,
        })
    );
    assert_eq!(core.submitted(), 16, "the refusal counts nothing");
    assert_eq!(core.core_id(), 3);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: exactly the queue depth is admitted, and one more is not.
#[test]
fn the_queue_depth_is_the_last_admissible_batch() -> Fallible {
    let mut core = RingCore::default();
    assert_eq!(core.submit(IOURING_QUEUE_DEPTH)?, IOURING_QUEUE_DEPTH);
    assert_eq!(core.submitted(), u64::from(IOURING_QUEUE_DEPTH));
    assert!(core.submit(IOURING_QUEUE_DEPTH.saturating_add(1)).is_err());
    assert_eq!(core.submit(0)?, 0, "an empty batch is not a refusal");
    assert!(core.is_drained());
    Ok(())
}
