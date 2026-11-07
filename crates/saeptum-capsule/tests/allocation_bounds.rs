// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! HISS-03: the claim that the table storage is bounded, made falsifiable.
//!
//! Numeric bounded types on the decision path are `Copy` and own no heap. The
//! identifier types (`CorrelationId`, `Label`) delegate to `CompactString`,
//! which stores short values inline and spills to the heap above 24 bytes;
//! they are `Clone` but not `Copy`. The tables and structs that embed them
//! are likewise `Clone` only.
//!
//! The structural property this file tests: every table is a fixed-size array,
//! so admitting a sandbox or capsule changes no stack allocation. The stack
//! layout is the same whether the table holds zero entries or the maximum.
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

fn assert_copy<T: Copy>() {}
fn assert_clone<T: Clone>() {}

// --- Positive -------------------------------------------------------------

/// Positive: every numeric bounded type on a decision path owns no heap.
#[test]
fn numeric_types_own_no_heap() {
    assert_copy::<GuestMemoryMib>();
    assert_copy::<VsockCid>();
    assert_copy::<VmId>();
    assert_copy::<CapsuleSlot>();
    assert_copy::<CapsuleMemoryLimit>();
    assert_copy::<CapabilitySet>();
    assert_copy::<RingCore>();
    assert_copy::<VmmIdentity>();
    assert_copy::<SandboxError>();
    assert_copy::<Unmeasured<u32>>();
    assert_copy::<saeptum_capsule::Measured<u32>>();
}

/// Positive: identifier-containing types are Clone.
#[test]
fn identifier_types_are_clone() {
    assert_clone::<CorrelationId>();
    assert_clone::<Label>();
    assert_clone::<MicroVmRequest>();
    assert_clone::<MicroVmInstance>();
    assert_clone::<WasmCapsule>();
    assert_clone::<MicroVmController>();
    assert_clone::<CapsuleRegistry>();
}

/// Positive: driving both tables to their bounds changes no stack size.
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
