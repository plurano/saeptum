// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! `saeptum-capsule`: the bounded microVM and `WebAssembly` capsule
//! controllers of the Saeptum sandbox library.
//!
//! The code moved here from Aegis OS `aegis-vesta` (placement
//! CUT-1632-03). What stays in Aegis are the operating system's own edge
//! contracts (the capsule request and the candidate evaluation), its decision
//! records and its requirement register; Aegis adapts those to the types of
//! this crate at its boundary.
//!
//! # Identifiers in this documentation
//!
//! Comments here cite the Aegis OS record the code was written against:
//! `REQ-P10-*` is a requirement of its sandbox component, `D58`, `D71` and
//! the like are its decision records, `M06`, `M21` and the like its
//! milestones, and `export-*` an imported source document with its digest
//! prefix. They are provenance, not dependencies: nothing in this crate reads
//! them, and the crate builds without the Aegis OS repository.
//!
//! # The things a reviewer should look at
//!
//! * [`MicroVmController`] holds the sandbox bound: [`MAX_MICROVMS`] rows, the
//!   next one refused, and terminating an identifier the table does not hold
//!   returns `false` rather than an error nobody reads.
//! * [`CapsuleRegistry`] holds the capsule bound the same way, and
//!   [`CapsuleSlot`] carries that bound into any value that names a slot.
//! * [`VmmIdentity`] names the monitor a sandbox runs under, so every figure a
//!   caller records can say which monitor produced it; [`VMM_PROBES`] records
//!   what the two probes returned on the reference profile.
//!
//! # The boot-time literal is not a measurement
//!
//! [`SCAFFOLD_BOOT_TIME_MS`], [`BOOT_TIME_TARGET_MS`] and
//! [`FOOTPRINT_TARGET_MIB`] are [`Unmeasured`] values: the sources state them
//! and nothing has measured them. `tests/unmeasured_literals.rs` keeps them
//! that way.
//!
//! # Design invariants (see `AGENTS.md`)
//!
//! * no recursion: every function here is a flat check, a bounded sweep or a
//!   field access, and no function in the crate calls itself directly or
//!   through another;
//! * every loop carries a scalar upper bound: [`MAX_MICROVMS`] and
//!   [`MAX_WASM_CAPSULES`];
//! * every value on a decision path is `Copy`, so no such path allocates;
//!   `tests/allocation_bounds.rs` is the falsifier;
//! * no `unwrap`, `expect`, `panic!`, slice indexing or unchecked arithmetic,
//!   and no `unsafe` (forbidden at the workspace root).
//!
//! # What this crate does not do
//!
//! It starts nothing and isolates nothing. There is no `KVM` ioctl, no
//! Firecracker or `QEMU` process, no jailer, no monitor API socket, no guest
//! kernel, no `WebAssembly` engine, no `AF_VSOCK` connection, no `io_uring`
//! ring and no filesystem access anywhere in it. A sandbox is a row in a fixed
//! array and a capsule is another. `tests/stubbed_effects.rs` sweeps the
//! crate's own sources for a recorded list of identifiers that would be needed
//! to do any of it and fails if one appears -- a regression gate over an
//! enumeration, not a proof over every such identifier.
//!
//! # Example
//!
//! ```
//! use saeptum_capsule::{
//!     CapabilitySet, Capability, CapsuleMemoryLimit, CapsuleRegistry, GuestMemoryMib, Label,
//!     MicroVmController, MicroVmRequest, VmmIdentity,
//! };
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sandboxes = MicroVmController::new();
//! let request = MicroVmRequest::new(
//!     Label::parse("agent-microvm-01")?,
//!     GuestMemoryMib::new(4)?,
//!     false,
//!     VmmIdentity::Firecracker,
//! )?;
//! let vm = sandboxes.spawn(request)?;
//! assert_eq!(sandboxes.count(), 1);
//! assert!(sandboxes.terminate(vm));
//! assert!(!sandboxes.terminate(saeptum_capsule::VmId::new(999)));
//!
//! let mut capsules = CapsuleRegistry::new();
//! let slot = capsules.register(
//!     Label::parse("capsule-01")?,
//!     CapsuleMemoryLimit::new(16 * 1024 * 1024)?,
//!     CapabilitySet::new().with(Capability::FilesystemRead),
//! )?;
//! assert_eq!(slot.get(), 1);
//! # Ok(())
//! # }
//! ```

pub mod capsule;
pub mod error;
pub mod id;
pub mod microvm;
pub mod ring;
pub mod unmeasured;
pub mod vmm;

pub use crate::capsule::{
    Capability, CapabilitySet, CapsuleMemoryLimit, CapsuleRegistry, CapsuleSlot,
    MAX_CAPSULE_MEMORY_BYTES, MAX_WASM_CAPSULES, MIN_CAPSULE_MEMORY_BYTES, WasmCapsule,
};
pub use crate::error::SandboxError;
pub use crate::id::{CorrelationId, IdError, Label, MAX_CORRELATION_LEN, MAX_LABEL_LEN};
pub use crate::microvm::{
    BOOT_TIME_TARGET_MS, FIRST_GUEST_CID, FIRST_VM_ID, FOOTPRINT_TARGET_MIB, GuestMemoryMib,
    MAX_GUEST_MEMORY_MIB, MAX_MICROVMS, MIN_GUEST_MEMORY_MIB, MicroVmController, MicroVmInstance,
    MicroVmRequest, SCAFFOLD_BOOT_TIME_MS, VmId, VmState, VsockCid,
};
pub use crate::ring::{IOURING_QUEUE_DEPTH, RingCore};
pub use crate::unmeasured::Unmeasured;
pub use crate::vmm::{VMM_PROBES, VmmIdentity, VmmProbe};
