// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The bounded capability-gated capsule table (REQ-P10-06, REQ-P10-08).
//!
//! This is the scaffold's `WasmCapsuleManager` with typed refusals, a
//! validated memory limit and a capability set that is a value rather than
//! four loose booleans. A capsule's slot is part of its identity, which is
//! what lets the P09 request name a slot and be refused at the bound.
//!
//! **No `WebAssembly` engine is here, and none is linked.** Nothing compiles,
//! validates, instantiates or executes a module; no host function is exported
//! and no memory is mapped. A capsule is a row in a fixed array, and its
//! capability set is a bitset nothing consults at runtime because there is no
//! runtime. Which engine would run it is the consumer's decision; Aegis OS
//! records its own as decision D06.

use crate::error::SandboxError;
use crate::id::Label;

/// Scalar upper bound on the capsule table (the scaffold's `MAX_WASM_CAPSULES`).
pub const MAX_WASM_CAPSULES: usize = 128;

/// The smallest capsule memory limit this table admits, in bytes.
pub const MIN_CAPSULE_MEMORY_BYTES: u64 = 64 * 1024;

/// The largest capsule memory limit this table admits, in bytes.
///
/// Sixty-four mebibytes: four times the scaffold's own sixteen, which keeps
/// the imported value comfortably inside the bound without admitting a limit
/// that would make the "many dormant sandboxes" claim of REQ-P10-01 absurd.
pub const MAX_CAPSULE_MEMORY_BYTES: u64 = 64 * 1024 * 1024;

/// The capabilities a capsule may be granted.
///
/// Deliberately an enumeration rather than four boolean fields: a set of
/// booleans has no name for what it contains, cannot be iterated, and makes
/// every constructor take four positional flags in the same order forever.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Capability {
    /// Outbound network access.
    Network,
    /// Reading from the host filesystem.
    FilesystemRead,
    /// Writing to the host filesystem.
    FilesystemWrite,
    /// The `Zenoh` inter-process transport.
    ZenohIpc,
}

impl Capability {
    /// Every capability, in the order the scaffold declares them.
    pub const ALL: [Self; 4] = [
        Self::Network,
        Self::FilesystemRead,
        Self::FilesystemWrite,
        Self::ZenohIpc,
    ];

    /// Returns the stable tag the wire form carries.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::FilesystemRead => "filesystem-read",
            Self::FilesystemWrite => "filesystem-write",
            Self::ZenohIpc => "zenoh-ipc",
        }
    }

    /// Returns the capability a wire tag names, when it names one.
    #[must_use]
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.tag() == tag)
    }

    /// Returns this capability's bit in a [`CapabilitySet`].
    #[must_use]
    pub const fn bit(self) -> u8 {
        match self {
            Self::Network => 0b0001,
            Self::FilesystemRead => 0b0010,
            Self::FilesystemWrite => 0b0100,
            Self::ZenohIpc => 0b1000,
        }
    }
}

/// A capsule's granted capabilities.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct CapabilitySet {
    bits: u8,
}

impl CapabilitySet {
    /// The set that grants nothing.
    pub const NONE: Self = Self { bits: 0 };

    /// Builds an empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self::NONE
    }

    /// Returns this set with `capability` granted.
    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self {
            bits: self.bits | capability.bit(),
        }
    }

    /// Returns `true` when `capability` is granted.
    #[must_use]
    pub const fn allows(self, capability: Capability) -> bool {
        self.bits & capability.bit() != 0
    }

    /// Returns how many capabilities are granted.
    #[must_use]
    pub fn count(self) -> usize {
        Capability::ALL
            .into_iter()
            .filter(|capability| self.allows(*capability))
            .count()
    }

    /// Returns `true` when nothing is granted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.bits == 0
    }
}

/// A validated capsule slot, numbered from one.
///
/// The slot is the capsule's place in the table and part of the P09 request,
/// so `1..=MAX_WASM_CAPSULES` is a bound on a payload field and not only on a
/// loop: a request naming slot 129 is refused before anything is admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CapsuleSlot(usize);

impl CapsuleSlot {
    /// The first admissible slot.
    pub const FIRST: Self = Self(1);

    /// The last admissible slot.
    pub const LAST: Self = Self(MAX_WASM_CAPSULES);

    /// Validates `slot` against `1..=MAX_WASM_CAPSULES`.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::SlotOutOfRange`] for zero and for anything past
    /// [`MAX_WASM_CAPSULES`].
    pub const fn new(slot: usize) -> Result<Self, SandboxError> {
        if slot < 1 || slot > MAX_WASM_CAPSULES {
            return Err(SandboxError::SlotOutOfRange {
                slot,
                max: MAX_WASM_CAPSULES,
            });
        }
        Ok(Self(slot))
    }

    /// Returns the validated slot number.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0
    }

    /// Returns the zero-based index this slot occupies.
    #[must_use]
    pub const fn index(self) -> usize {
        self.0.saturating_sub(1)
    }
}

/// A validated capsule memory limit, in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CapsuleMemoryLimit(u64);

impl CapsuleMemoryLimit {
    /// Validates `bytes` against
    /// `MIN_CAPSULE_MEMORY_BYTES..=MAX_CAPSULE_MEMORY_BYTES`.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::MemoryLimitOutOfRange`] outside that range.
    pub const fn new(bytes: u64) -> Result<Self, SandboxError> {
        if bytes < MIN_CAPSULE_MEMORY_BYTES || bytes > MAX_CAPSULE_MEMORY_BYTES {
            return Err(SandboxError::MemoryLimitOutOfRange {
                bytes,
                min: MIN_CAPSULE_MEMORY_BYTES,
                max: MAX_CAPSULE_MEMORY_BYTES,
            });
        }
        Ok(Self(bytes))
    }

    /// Returns the validated limit in bytes.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// One capsule row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WasmCapsule {
    /// The slot the capsule occupies.
    pub slot: CapsuleSlot,
    /// The capsule name.
    pub name: Label,
    /// The memory limit the capsule was admitted with.
    pub memory_limit: CapsuleMemoryLimit,
    /// The capabilities the capsule was granted.
    pub capabilities: CapabilitySet,
}

/// The bounded capsule table.
#[derive(Debug, Clone, Copy)]
pub struct CapsuleRegistry {
    capsules: [Option<WasmCapsule>; MAX_WASM_CAPSULES],
    count: usize,
}

impl Default for CapsuleRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CapsuleRegistry {
    /// Builds an empty table.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            capsules: [None; MAX_WASM_CAPSULES],
            count: 0,
        }
    }

    /// Admits one capsule at the next free slot and returns that slot.
    ///
    /// # Errors
    ///
    /// Returns [`SandboxError::CapsuleTableFull`] at [`MAX_WASM_CAPSULES`], and
    /// [`SandboxError::SlotOutOfRange`] if the next slot would be past the
    /// bound, which the count check already excludes and which is returned
    /// rather than assumed away.
    pub fn register(
        &mut self,
        name: Label,
        memory_limit: CapsuleMemoryLimit,
        capabilities: CapabilitySet,
    ) -> Result<CapsuleSlot, SandboxError> {
        if self.count >= MAX_WASM_CAPSULES {
            return Err(SandboxError::CapsuleTableFull {
                max: MAX_WASM_CAPSULES,
            });
        }
        let slot = CapsuleSlot::new(self.count.saturating_add(1))?;
        let capsule = WasmCapsule {
            slot,
            name,
            memory_limit,
            capabilities,
        };
        let cell = self
            .capsules
            .get_mut(slot.index())
            .ok_or(SandboxError::CapsuleTableFull {
                max: MAX_WASM_CAPSULES,
            })?;
        *cell = Some(capsule);
        self.count = self.count.saturating_add(1);
        Ok(slot)
    }

    /// Returns the capsule in `slot`, when the table holds one.
    #[must_use]
    pub fn get(&self, slot: CapsuleSlot) -> Option<WasmCapsule> {
        self.capsules.get(slot.index()).copied().flatten()
    }

    /// Returns how many capsules the table holds.
    #[must_use]
    pub const fn count(&self) -> usize {
        self.count
    }

    /// Returns `true` when the table holds no capsule.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns how much memory the admitted capsules are permitted, in bytes.
    ///
    /// Saturating on purpose: the figure is a budget report, and a table at
    /// its bound with every capsule at the maximum limit is still far below
    /// `u64::MAX`, so saturation is unreachable rather than silently wrong.
    #[must_use]
    pub fn permitted_memory_bytes(&self) -> u64 {
        self.capsules
            .iter()
            .take(MAX_WASM_CAPSULES)
            .flatten()
            .fold(0u64, |total, capsule| {
                total.saturating_add(capsule.memory_limit.get())
            })
    }
}
