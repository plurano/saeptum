// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bounded microVM sandbox table (REQ-P10-01, REQ-P10-05, REQ-P10-06).
//!
//! This is the scaffold's `MicroVmController` with the three things it lacked:
//! the capacity refusal is a typed error rather than a `&'static str`, the
//! guest memory size and the `vsock` context identifier are validated instead
//! of copied, and the boot time a row carries is a [`Measured`] figure that
//! names its monitor, or none at all.
//!
//! **Nothing here boots anything.** No process is started, no `/dev/kvm` is
//! opened, no jailer is configured, no API socket is created and no guest
//! kernel is loaded. A sandbox is a row in a fixed array; "running" is a value
//! of [`VmState`]. Which monitor a row names is carried, never chosen for it:
//! see [`VmmIdentity`].

use crate::error::SandboxError;
use crate::id::Label;
use crate::measured::Measured;
use crate::unmeasured::Unmeasured;
use crate::vmm::VmmIdentity;

/// Scalar upper bound on the microVM table (the scaffold's `MAX_MICROVMS`).
pub const MAX_MICROVMS: usize = 64;

/// The first sandbox identifier handed out, kept from the scaffold.
pub const FIRST_VM_ID: u32 = 100;

/// The lowest `vsock` context identifier a guest may hold.
///
/// Zero, one and two are reserved by the protocol for the hypervisor, the
/// local and the host context, so the first guest identifier is three.
pub const FIRST_GUEST_CID: u32 = 3;

/// The smallest guest memory size this table admits, in mebibytes.
pub const MIN_GUEST_MEMORY_MIB: u32 = 1;

/// The largest guest memory size this table admits, in mebibytes.
pub const MAX_GUEST_MEMORY_MIB: u32 = 1024;

/// The boot time the scaffold writes into every sandbox it creates.
///
/// Replaces the scaffold's literal 112 (export-037 `ce490c88081f`, "Sub-125ms
/// cold boot speed"), which REQ-P10-05 recorded as unmeasured. Aegis OS run
/// r20261017T124857-0027 of `make verify-workstation` booted 64 Firecracker 1.17.0
/// microVMs with the boot timer on; this is the median of their
/// `Guest-boot-time` wall clock, 306210 us, in whole milliseconds. The timer
/// starts when Firecracker begins building the microVM.
pub const MEASURED_BOOT_TIME_MS: Measured<u32> =
    Measured::new(306, VmmIdentity::Firecracker, "r20261017T124857-0027");

/// The measured footprint of one Firecracker monitor process, in kibibytes.
///
/// The median `VmRSS` of the same run's 64 Firecracker 1.17.0 processes after
/// each microVM's first answer. It is the monitor's resident set: its own
/// memory plus the part of the 64 MiB guest it has touched, not the guest's
/// view of its memory.
pub const MEASURED_FOOTPRINT_KIB: Measured<u32> =
    Measured::new(61_620, VmmIdentity::Firecracker, "r20261017T124857-0027");

/// The cold-boot target the P10 report states, in milliseconds.
///
/// Recorded from export-018 `5dbc6d071bbb` (REQ-P10-01). A target is not a
/// measurement and stays [`Unmeasured`]; [`MEASURED_BOOT_TIME_MS`] is the
/// figure held against it, and misses it.
pub const BOOT_TIME_TARGET_MS: Unmeasured<u32> = Unmeasured::new(125);

/// The resident footprint target the P10 report states, in mebibytes.
///
/// Recorded from export-018 `5dbc6d071bbb` (REQ-P10-01), on the same terms as
/// [`BOOT_TIME_TARGET_MS`]; [`MEASURED_FOOTPRINT_KIB`] is held against it, and
/// misses it.
pub const FOOTPRINT_TARGET_MIB: Unmeasured<u32> = Unmeasured::new(5);

/// A sandbox identifier.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct VmId(u32);

impl VmId {
    /// Names a sandbox by its raw identifier.
    #[must_use]
    pub const fn new(raw: u32) -> Self {
        Self(raw)
    }

    /// Returns the raw identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A validated guest memory size, in mebibytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuestMemoryMib(u32);

impl GuestMemoryMib {
    /// Validates `mib` against `MIN_GUEST_MEMORY_MIB..=MAX_GUEST_MEMORY_MIB`.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::GuestMemoryOutOfRange`] outside that range, so a
    /// zero-sized or absurd guest never becomes a value.
    pub const fn new(mib: u32) -> Result<Self, SandboxError> {
        if mib < MIN_GUEST_MEMORY_MIB || mib > MAX_GUEST_MEMORY_MIB {
            return Err(SandboxError::GuestMemoryOutOfRange {
                mib,
                min: MIN_GUEST_MEMORY_MIB,
                max: MAX_GUEST_MEMORY_MIB,
            });
        }
        Ok(Self(mib))
    }

    /// Returns the validated size in mebibytes.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// A validated guest `vsock` context identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct VsockCid(u32);

impl VsockCid {
    /// Validates `cid` against the reserved low identifiers.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::VsockCidOutOfRange`] below [`FIRST_GUEST_CID`].
    pub const fn new(cid: u32) -> Result<Self, SandboxError> {
        if cid < FIRST_GUEST_CID {
            return Err(SandboxError::VsockCidOutOfRange {
                cid,
                min: FIRST_GUEST_CID,
            });
        }
        Ok(Self(cid))
    }

    /// Returns the validated context identifier.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The lifecycle states a sandbox row may be in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VmState {
    /// Declared and not started.
    Uninitialised,
    /// Started and not yet serving.
    Booting,
    /// Serving.
    Running,
    /// Suspended.
    Paused,
    /// Stopped for good.
    Terminated,
}

impl VmState {
    /// Returns the stable name this state is recorded under.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Uninitialised => "uninitialised",
            Self::Booting => "booting",
            Self::Running => "running",
            Self::Paused => "paused",
            Self::Terminated => "terminated",
        }
    }
}

/// What a caller asks the table for.
///
/// A request is validated on construction, so the table stores decided values
/// and never re-checks them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicroVmRequest {
    /// The sandbox name.
    pub name: Label,
    /// The guest memory size.
    pub memory: GuestMemoryMib,
    /// Whether the sandbox asks for an accelerator.
    pub accelerator: bool,
    /// The monitor that would run it.
    pub vmm: VmmIdentity,
}

impl MicroVmRequest {
    /// Builds a request, refusing an accelerator the monitor cannot provide.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::AcceleratorUnsupported`] when `accelerator` is
    /// set and `vmm` has no `PCI` passthrough. The scaffold sets its
    /// `is_gpu_enabled` flag on a Firecracker sandbox, which D58 records as
    /// the fact that forces the monitor question rather than deferring it.
    pub const fn new(
        name: Label,
        memory: GuestMemoryMib,
        accelerator: bool,
        vmm: VmmIdentity,
    ) -> Result<Self, SandboxError> {
        if accelerator && !vmm.supports_pci_passthrough() {
            return Err(SandboxError::AcceleratorUnsupported { vmm });
        }
        Ok(Self {
            name,
            memory,
            accelerator,
            vmm,
        })
    }
}

/// One sandbox row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MicroVmInstance {
    /// The sandbox identifier.
    pub vm_id: VmId,
    /// The sandbox name.
    pub name: Label,
    /// The guest memory size.
    pub memory: GuestMemoryMib,
    /// The guest `vsock` context identifier.
    pub vsock_cid: VsockCid,
    /// Whether the sandbox asked for an accelerator.
    pub accelerator: bool,
    /// The monitor this row names.
    pub vmm: VmmIdentity,
    /// The lifecycle state.
    pub state: VmState,
    /// The measured boot time of the row's monitor, or `None` when no
    /// figure was measured on it (D58: never another monitor's figure).
    pub measured_boot_time_ms: Option<Measured<u32>>,
}

/// The bounded sandbox table.
///
/// `Copy`, like every value on a decision path in this crate: the whole table
/// is a fixed array, so admitting a sandbox allocates nothing.
#[derive(Debug, Clone, Copy)]
pub struct MicroVmController {
    instances: [Option<MicroVmInstance>; MAX_MICROVMS],
    count: usize,
}

impl Default for MicroVmController {
    fn default() -> Self {
        Self::new()
    }
}

impl MicroVmController {
    /// Builds an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            instances: [None; MAX_MICROVMS],
            count: 0,
        }
    }

    /// Admits one sandbox and returns its identifier.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::MicroVmTableFull`] at [`MAX_MICROVMS`], and
    /// [`SandboxError::VsockCidOutOfRange`] if the derived context identifier
    /// would be a reserved one, which cannot happen for a table this size and
    /// is returned rather than assumed away.
    pub fn spawn(&mut self, request: MicroVmRequest) -> Result<VmId, SandboxError> {
        if self.count >= MAX_MICROVMS {
            return Err(SandboxError::MicroVmTableFull { max: MAX_MICROVMS });
        }
        let index = self.count;
        let raw = FIRST_VM_ID.saturating_add(u32::try_from(index).unwrap_or(u32::MAX));
        let vm_id = VmId::new(raw);
        let instance = MicroVmInstance {
            vm_id,
            name: request.name,
            memory: request.memory,
            vsock_cid: VsockCid::new(FIRST_GUEST_CID.saturating_add(raw))?,
            accelerator: request.accelerator,
            vmm: request.vmm,
            state: VmState::Running,
            measured_boot_time_ms: MEASURED_BOOT_TIME_MS.for_vmm(request.vmm),
        };
        let slot = self
            .instances
            .get_mut(index)
            .ok_or(SandboxError::MicroVmTableFull { max: MAX_MICROVMS })?;
        *slot = Some(instance);
        self.count = self.count.saturating_add(1);
        Ok(vm_id)
    }

    /// Terminates one sandbox, returning `false` for an identifier it does not
    /// hold.
    ///
    /// The bounded sweep is the scaffold's, and so is the `bool`: a caller
    /// that asks to stop something that was never started learns that from the
    /// return value rather than from an error it might ignore.
    pub fn terminate(&mut self, vm_id: VmId) -> bool {
        for slot in self.instances.iter_mut().take(MAX_MICROVMS) {
            if let Some(instance) = slot.as_mut()
                && instance.vm_id == vm_id
            {
                instance.state = VmState::Terminated;
                return true;
            }
        }
        false
    }

    /// Returns the row for `vm_id`, when the table holds one.
    #[must_use]
    pub fn get(&self, vm_id: VmId) -> Option<MicroVmInstance> {
        self.instances
            .iter()
            .take(MAX_MICROVMS)
            .flatten()
            .find(|instance| instance.vm_id == vm_id)
            .copied()
    }

    /// Returns how many sandboxes the table holds.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` when the table holds no sandbox.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns how many rows are in [`VmState::Running`].
    #[must_use]
    pub fn running(&self) -> usize {
        self.instances
            .iter()
            .take(MAX_MICROVMS)
            .flatten()
            .filter(|instance| instance.state == VmState::Running)
            .count()
    }
}
