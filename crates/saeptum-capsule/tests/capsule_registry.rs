// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E06-2: the bounded capsule table and its capability set.
//!
//! Positive: 128 capsules are accepted. Negative: an unknown slot holds
//! nothing and a capability that was not granted is not allowed. Boundary: the
//! 129th capsule is refused, and slot 128 is the last one that parses.
//!
//! Nothing here loads a `WebAssembly` module.

mod common;

use saeptum_capsule::{
    Capability, CapabilitySet, CapsuleMemoryLimit, CapsuleRegistry, CapsuleSlot, MAX_WASM_CAPSULES,
    SandboxError, WasmCapsule,
};

use common::{CAPSULE, CAPSULE_BYTES, Fallible, filled_registry, label, scaffold_capabilities};

// --- Positive -------------------------------------------------------------

/// Positive: the table accepts the full 128 capsules.
#[test]
fn the_table_accepts_one_hundred_and_twenty_eight_capsules() -> Fallible {
    let registry = filled_registry(MAX_WASM_CAPSULES)?;
    assert_eq!(registry.count(), MAX_WASM_CAPSULES);
    assert!(!registry.is_empty());
    let expected = CAPSULE_BYTES.saturating_mul(u64::try_from(MAX_WASM_CAPSULES).unwrap_or(0));
    assert_eq!(registry.permitted_memory_bytes(), expected);
    Ok(())
}

/// Positive: a registered capsule is readable in the slot it was given.
#[test]
fn a_registered_capsule_is_readable_in_its_slot() -> Fallible {
    let mut registry = CapsuleRegistry::new();
    assert!(registry.is_empty());
    let slot = registry.register(
        label(CAPSULE)?,
        CapsuleMemoryLimit::new(CAPSULE_BYTES)?,
        scaffold_capabilities(),
    )?;
    assert_eq!(slot, CapsuleSlot::FIRST);
    assert_eq!(slot.index(), 0);
    let capsule: WasmCapsule = registry
        .get(slot)
        .ok_or("the table must hold the capsule it just registered")?;
    assert_eq!(capsule.slot, slot);
    assert_eq!(capsule.name, label(CAPSULE)?);
    assert_eq!(capsule.memory_limit.get(), CAPSULE_BYTES);
    assert_eq!(capsule.capabilities, scaffold_capabilities());
    Ok(())
}

/// Positive: the capability set grants what it was built with, and nothing
/// else.
#[test]
fn the_capability_set_grants_what_it_was_built_with() {
    let granted = scaffold_capabilities();
    assert!(granted.allows(Capability::FilesystemRead));
    assert!(granted.allows(Capability::ZenohIpc));
    assert!(!granted.allows(Capability::Network));
    assert!(!granted.allows(Capability::FilesystemWrite));
    assert_eq!(granted.count(), 2);
    assert!(!granted.is_empty());
    for capability in Capability::ALL {
        assert_eq!(Capability::from_tag(capability.tag()), Some(capability));
        assert!(capability.bit() != 0);
    }
    let repeated = CapabilitySet::NONE
        .with(Capability::Network)
        .with(Capability::Network);
    assert!(repeated.allows(Capability::Network));
}

// --- Negative -------------------------------------------------------------

/// Negative: an empty set allows nothing, and an unregistered slot holds
/// nothing.
#[test]
fn an_empty_set_allows_nothing_and_an_empty_slot_holds_nothing() -> Fallible {
    let empty = CapabilitySet::NONE;
    assert_eq!(empty, CapabilitySet::new());
    assert!(empty.is_empty());
    assert_eq!(empty.count(), 0);
    for capability in Capability::ALL {
        assert!(!empty.allows(capability));
    }
    let registry = filled_registry(1)?;
    assert!(registry.get(CapsuleSlot::new(2)?).is_none());
    assert!(Capability::from_tag("wasi-clock").is_none());
    Ok(())
}

/// Negative: a memory limit outside the declared range is refused, and the
/// refusal names the range.
#[test]
fn a_memory_limit_outside_the_range_is_refused() {
    let refused = CapsuleMemoryLimit::new(0);
    assert_eq!(
        refused,
        Err(SandboxError::MemoryLimitOutOfRange {
            bytes: 0,
            min: saeptum_capsule::MIN_CAPSULE_MEMORY_BYTES,
            max: saeptum_capsule::MAX_CAPSULE_MEMORY_BYTES,
        })
    );
    assert!(
        CapsuleMemoryLimit::new(saeptum_capsule::MAX_CAPSULE_MEMORY_BYTES.saturating_add(1))
            .is_err()
    );
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the 128th capsule is accepted and the 129th is refused.
#[test]
fn the_one_hundred_and_twenty_ninth_capsule_is_refused() -> Fallible {
    let mut registry = filled_registry(MAX_WASM_CAPSULES.saturating_sub(1))?;
    assert_eq!(registry.count(), 127);
    let last = registry.register(
        label(CAPSULE)?,
        CapsuleMemoryLimit::new(CAPSULE_BYTES)?,
        CapabilitySet::new(),
    )?;
    assert_eq!(last, CapsuleSlot::LAST);
    assert_eq!(last.get(), MAX_WASM_CAPSULES);
    let refused = registry.register(
        label(CAPSULE)?,
        CapsuleMemoryLimit::new(CAPSULE_BYTES)?,
        CapabilitySet::new(),
    );
    assert_eq!(refused, Err(SandboxError::CapsuleTableFull { max: 128 }));
    assert_eq!(
        registry.count(),
        MAX_WASM_CAPSULES,
        "the refusal stores nothing"
    );
    Ok(())
}

/// Boundary: the slot range is `1..=128` at both ends.
#[test]
fn the_slot_range_is_closed_at_both_ends() -> Fallible {
    assert_eq!(CapsuleSlot::new(1)?, CapsuleSlot::FIRST);
    assert_eq!(CapsuleSlot::new(MAX_WASM_CAPSULES)?, CapsuleSlot::LAST);
    assert_eq!(
        CapsuleSlot::new(0),
        Err(SandboxError::SlotOutOfRange { slot: 0, max: 128 })
    );
    assert_eq!(
        CapsuleSlot::new(MAX_WASM_CAPSULES.saturating_add(1)),
        Err(SandboxError::SlotOutOfRange {
            slot: 129,
            max: 128
        })
    );
    assert_eq!(
        CapsuleSlot::LAST.index(),
        MAX_WASM_CAPSULES.saturating_sub(1)
    );
    Ok(())
}

/// Boundary: the memory limit range is closed at both ends.
#[test]
fn the_memory_limit_range_is_closed_at_both_ends() -> Fallible {
    assert_eq!(saeptum_capsule::MIN_CAPSULE_MEMORY_BYTES, 64 * 1024);
    assert_eq!(
        CapsuleMemoryLimit::new(saeptum_capsule::MIN_CAPSULE_MEMORY_BYTES)?.get(),
        saeptum_capsule::MIN_CAPSULE_MEMORY_BYTES
    );
    assert_eq!(
        CapsuleMemoryLimit::new(saeptum_capsule::MAX_CAPSULE_MEMORY_BYTES)?.get(),
        saeptum_capsule::MAX_CAPSULE_MEMORY_BYTES
    );
    assert!(
        CapsuleMemoryLimit::new(saeptum_capsule::MIN_CAPSULE_MEMORY_BYTES.saturating_sub(1))
            .is_err()
    );
    assert!(CapsuleMemoryLimit::new(64 * 1024 - 1).is_err());
    Ok(())
}
