// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The submission-queue bound (REQ-P10-04).
//!
//! REQ-P10-04 asks P10 to use `io_uring` so asynchronous sandboxing does not
//! bottleneck the fast loop, and the scaffold's `IoUringThreadCore` stands for
//! that: a per-core pair of counters and a poll that returns a fixed four.
//!
//! **There is no `io_uring` here.** No ring is set up, no file descriptor is
//! registered, no submission or completion queue is mapped and no syscall is
//! made. What survives the removal of the effect is the one checkable rule:
//! a batch larger than the declared queue depth cannot be submitted. That is a
//! bound, and a bound is testable without a kernel.

use crate::error::SandboxError;

/// The submission queue depth the scaffold declares.
pub const IOURING_QUEUE_DEPTH: u32 = 1024;

/// One core's submission and completion accounting.
///
/// The scaffold uses two atomics; this crate uses plain counters because the
/// slice is single-threaded by construction and an atomic would suggest a
/// concurrency story the milestone does not deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RingCore {
    core_id: usize,
    submitted: u64,
    completed: u64,
}

impl RingCore {
    /// Builds the accounting for one core.
    #[must_use]
    pub const fn new(core_id: usize) -> Self {
        Self {
            core_id,
            submitted: 0,
            completed: 0,
        }
    }

    /// Returns the core this accounting belongs to.
    #[must_use]
    pub const fn core_id(&self) -> usize {
        self.core_id
    }

    /// Records a submission batch and the completions it produces.
    ///
    /// Every entry submitted is counted as completed, which is what makes this
    /// accounting and not an implementation: a real ring completes when the
    /// kernel says so.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::BatchOverQueueDepth`] for a batch larger than
    /// [`IOURING_QUEUE_DEPTH`].
    pub fn submit(&mut self, entries: u32) -> Result<u32, SandboxError> {
        if entries > IOURING_QUEUE_DEPTH {
            return Err(SandboxError::BatchOverQueueDepth {
                entries,
                depth: IOURING_QUEUE_DEPTH,
            });
        }
        self.submitted = self.submitted.saturating_add(u64::from(entries));
        self.completed = self.completed.saturating_add(u64::from(entries));
        Ok(entries)
    }

    /// Returns how many entries have been submitted.
    #[must_use]
    pub const fn submitted(&self) -> u64 {
        self.submitted
    }

    /// Returns how many entries have completed.
    #[must_use]
    pub const fn completed(&self) -> u64 {
        self.completed
    }

    /// Returns `true` when nothing is outstanding.
    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.submitted == self.completed
    }
}
