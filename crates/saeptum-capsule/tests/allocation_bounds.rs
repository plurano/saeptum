// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-03: the claim that no decision path allocates, made falsifiable.
//!
//! The reason this crate can say a decision path allocates nothing is
//! structural: every value on such a path is `Copy`, so admitting a sandbox or
//! a capsule writes into storage that already exists. `assert_no_heap::<T>()`
//! is the executable form: a `Vec`, `String` or `Box` anywhere inside one of
//! these types, at any depth, removes `Copy` and this file stops compiling,
//! which fails the gate.
//!
//! # What is not claimed here
//!
//! Decoding is not covered: this crate defines no wire payload. The payloads
//! a consumer builds around these values, and whether decoding them
//! allocates, are that consumer's claim to make and test.

mod common;

use core::mem::size_of;

use saeptum_capsule::{
    CapabilitySet, CapsuleMemoryLimit, CapsuleRegistry, CapsuleSlot, CorrelationId, GuestMemoryMib,
    Label, MicroVmController, MicroVmInstance, MicroVmRequest, RingCore, SandboxError, Unmeasured,
    VmId, VmmIdentity, VsockCid, WasmCapsule,
};

use common::Fallible;

/// Accepts only a type that owns no heap, because it is `Copy`.
fn assert_no_heap<T: Copy>() {}

// --- Positive -------------------------------------------------------------

/// Positive: every value on a decision path owns no heap.
///
/// This is the falsifier. Adding a `Vec`, `String` or `Box` to any of these
/// types, or to anything they contain, removes `Copy` and this test stops
/// compiling.
#[test]
fn every_value_on_a_decision_path_owns_no_heap() {
    assert_no_heap::<MicroVmController>();
    assert_no_heap::<MicroVmInstance>();
    assert_no_heap::<MicroVmRequest>();
    assert_no_heap::<GuestMemoryMib>();
    assert_no_heap::<VsockCid>();
    assert_no_heap::<VmId>();
    assert_no_heap::<CapsuleRegistry>();
    assert_no_heap::<WasmCapsule>();
    assert_no_heap::<CapsuleSlot>();
    assert_no_heap::<CapsuleMemoryLimit>();
    assert_no_heap::<CapabilitySet>();
    assert_no_heap::<CorrelationId>();
    assert_no_heap::<Label>();
    assert_no_heap::<RingCore>();
    assert_no_heap::<VmmIdentity>();
    assert_no_heap::<SandboxError>();
    assert_no_heap::<Unmeasured<u32>>();
}

/// Positive: driving both tables to their bounds changes no size.
#[test]
fn driving_the_tables_changes_no_storage() -> Fallible {
    let controller = common::filled_controller(saeptum_capsule::MAX_MICROVMS)?;
    let registry = common::filled_registry(saeptum_capsule::MAX_WASM_CAPSULES)?;
    assert_eq!(size_of_val(&controller), size_of::<MicroVmController>());
    assert_eq!(size_of_val(&registry), size_of::<CapsuleRegistry>());
    assert!(size_of::<MicroVmController>() > size_of::<MicroVmInstance>());
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a table at its bound refuses the next row without growing.
#[test]
fn a_full_table_refuses_without_growing() -> Fallible {
    let mut controller = common::filled_controller(saeptum_capsule::MAX_MICROVMS)?;
    let refused = controller.spawn(common::sandbox_request(VmmIdentity::Firecracker)?);
    assert!(refused.is_err());
    assert_eq!(size_of_val(&controller), size_of::<MicroVmController>());
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: an empty table and a full one occupy the same storage.
#[test]
fn empty_and_full_tables_occupy_the_same_storage() -> Fallible {
    let empty = CapsuleRegistry::new();
    let full = common::filled_registry(saeptum_capsule::MAX_WASM_CAPSULES)?;
    assert!(empty.is_empty());
    assert_eq!(full.count(), saeptum_capsule::MAX_WASM_CAPSULES);
    assert_eq!(size_of_val(&empty), size_of_val(&full));
    Ok(())
}
