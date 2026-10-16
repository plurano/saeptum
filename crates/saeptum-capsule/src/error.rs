// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! What the P10 controllers refuse, and why.
//!
//! The imported scaffold returns `&'static str` from every controller, so a
//! caller can only match on prose, and the two capacity refusals are
//! indistinguishable to a program. Each refusal is a variant here instead, and
//! each carries the bound it hit, so a test asserts the bound rather than a
//! sentence.

use crate::id::IdError;
use crate::vmm::VmmIdentity;

/// Reasons a P10 controller refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SandboxError {
    /// The microVM table is full.
    #[error("the microVM table holds its maximum of {max} sandboxes")]
    MicroVmTableFull {
        /// The scalar bound that was hit.
        max: usize,
    },
    /// The capsule table is full.
    #[error("the capsule table holds its maximum of {max} capsules")]
    CapsuleTableFull {
        /// The scalar bound that was hit.
        max: usize,
    },
    /// A capsule slot was outside the admissible range.
    #[error("a capsule slot of {slot} is outside 1..={max}")]
    SlotOutOfRange {
        /// The slot that was offered.
        slot: usize,
        /// The largest admissible slot.
        max: usize,
    },
    /// A memory limit was outside the admissible range.
    #[error("a memory limit of {bytes} bytes is outside {min}..={max}")]
    MemoryLimitOutOfRange {
        /// The limit that was offered.
        bytes: u64,
        /// The smallest admissible limit.
        min: u64,
        /// The largest admissible limit.
        max: u64,
    },
    /// A guest memory size was outside the admissible range.
    #[error("a guest memory size of {mib} MiB is outside {min}..={max}")]
    GuestMemoryOutOfRange {
        /// The size that was offered.
        mib: u32,
        /// The smallest admissible size.
        min: u32,
        /// The largest admissible size.
        max: u32,
    },
    /// A submission batch was larger than the ring can hold.
    #[error("a submission batch of {entries} exceeds the queue depth of {depth}")]
    BatchOverQueueDepth {
        /// The batch that was offered.
        entries: u32,
        /// The declared queue depth.
        depth: u32,
    },
    /// A `vsock` context identifier was below the first guest identifier.
    #[error("a vsock context identifier of {cid} is below the first guest identifier {min}")]
    VsockCidOutOfRange {
        /// The identifier that was offered.
        cid: u32,
        /// The lowest admissible identifier.
        min: u32,
    },
    /// A sandbox asked for an accelerator its monitor cannot pass through.
    #[error("{vmm:?} has no PCI passthrough, so it cannot give a sandbox an accelerator")]
    AcceleratorUnsupported {
        /// The monitor that was named.
        vmm: VmmIdentity,
    },
    /// An identifier was refused by its validating constructor.
    #[error("an identifier was refused: {0}")]
    Identifier(#[from] IdError),
}
