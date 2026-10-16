// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Epic E06-2: the bounded microVM table.
//!
//! Positive: 64 sandboxes are accepted. Negative: terminating an identifier
//! the table does not hold returns `false`. Boundary: the 65th sandbox is
//! refused, and the refusal names the bound it hit.
//!
//! Nothing here boots anything. A pass is evidence about a fixed array.

mod common;

use saeptum_capsule::{
    FIRST_GUEST_CID, FIRST_VM_ID, GuestMemoryMib, MAX_MICROVMS, MicroVmController, MicroVmInstance,
    MicroVmRequest, SCAFFOLD_BOOT_TIME_MS, SandboxError, VmId, VmState, VmmIdentity, VsockCid,
};

use common::{Fallible, GUEST_MIB, SANDBOX, filled_controller, label, sandbox_request};

// --- Positive -------------------------------------------------------------

/// Positive: the table accepts the full 64 sandboxes, and every row is running.
#[test]
fn the_table_accepts_sixty_four_sandboxes() -> Fallible {
    let controller = filled_controller(MAX_MICROVMS)?;
    assert_eq!(controller.count(), MAX_MICROVMS);
    assert_eq!(controller.running(), MAX_MICROVMS);
    assert!(!controller.is_empty());
    Ok(())
}

/// Positive: a spawned sandbox is readable, and carries what it was asked for.
#[test]
fn a_spawned_sandbox_carries_its_request() -> Fallible {
    let mut controller = MicroVmController::new();
    assert!(controller.is_empty());
    let id = controller.spawn(sandbox_request(VmmIdentity::QemuMicrovm)?)?;
    assert_eq!(id, VmId::new(FIRST_VM_ID));
    let row: MicroVmInstance = controller
        .get(id)
        .ok_or("the table must hold the sandbox it just spawned")?;
    assert_eq!(row.vm_id, id);
    assert_eq!(row.name, label(SANDBOX)?);
    assert_eq!(row.memory, GuestMemoryMib::new(GUEST_MIB)?);
    assert_eq!(row.vmm, VmmIdentity::QemuMicrovm);
    Ok(())
}

/// Positive: a spawned sandbox is running, unaccelerated, and carries the
/// derived context identifier and the recorded boot-time literal.
#[test]
fn a_spawned_sandbox_carries_its_derived_fields() -> Fallible {
    let mut controller = MicroVmController::new();
    let id = controller.spawn(sandbox_request(VmmIdentity::Firecracker)?)?;
    let row = controller
        .get(id)
        .ok_or("the table must hold the sandbox it just spawned")?;
    assert_eq!(row.state, VmState::Running);
    assert!(!row.accelerator);
    assert_eq!(
        row.vsock_cid,
        VsockCid::new(FIRST_GUEST_CID.saturating_add(FIRST_VM_ID))?
    );
    assert_eq!(row.declared_boot_time_ms, SCAFFOLD_BOOT_TIME_MS);
    Ok(())
}

/// Positive: terminating a sandbox the table holds succeeds and is visible.
#[test]
fn terminating_a_known_sandbox_succeeds() -> Fallible {
    let mut controller = MicroVmController::new();
    let id = controller.spawn(sandbox_request(VmmIdentity::Firecracker)?)?;
    assert!(controller.terminate(id));
    let row = controller.get(id).ok_or("the row must still be readable")?;
    assert_eq!(row.state, VmState::Terminated);
    assert_eq!(row.state.name(), "terminated");
    assert_eq!(controller.running(), 0);
    assert_eq!(controller.count(), 1, "termination frees no slot");
    Ok(())
}

/// Positive: every lifecycle state has a distinct recorded name, including the
/// three no controller path reaches yet.
///
/// `Uninitialised`, `Booting` and `Paused` exist because the scaffold declares
/// them and a monitor would drive a sandbox through them. Nothing here does,
/// and recording that they are unreachable from this crate's own API is more
/// honest than deleting states the subsystem has.
#[test]
fn every_lifecycle_state_has_a_distinct_name() -> Fallible {
    let states = [
        (VmState::Uninitialised, "uninitialised"),
        (VmState::Booting, "booting"),
        (VmState::Running, "running"),
        (VmState::Paused, "paused"),
        (VmState::Terminated, "terminated"),
    ];
    let mut names: Vec<&str> = states.iter().map(|(_, name)| *name).collect();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), 5, "every state has a distinct recorded name");
    for (state, name) in states {
        assert_eq!(state.name(), name);
    }
    let controller = filled_controller(1)?;
    let row = controller
        .get(VmId::new(FIRST_VM_ID))
        .ok_or("the table must hold the sandbox")?;
    for unreachable in [VmState::Uninitialised, VmState::Booting, VmState::Paused] {
        assert_ne!(
            row.state,
            unreachable,
            "no path in this crate produces {}",
            unreachable.name()
        );
    }
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: terminating an unknown identifier returns `false`.
#[test]
fn terminating_an_unknown_sandbox_returns_false() -> Fallible {
    let mut controller = MicroVmController::new();
    assert!(!controller.terminate(VmId::new(999)));
    controller.spawn(sandbox_request(VmmIdentity::Firecracker)?)?;
    assert!(!controller.terminate(VmId::new(999)));
    assert!(controller.get(VmId::new(999)).is_none());
    assert_eq!(controller.running(), 1, "the known row is untouched");
    Ok(())
}

/// Negative: an accelerator is refused on a monitor that cannot pass one
/// through, which is the second fact decision D58 rests on.
#[test]
fn an_accelerator_is_refused_on_a_monitor_without_passthrough() -> Fallible {
    let refused = MicroVmRequest::new(
        label(SANDBOX)?,
        GuestMemoryMib::new(GUEST_MIB)?,
        true,
        VmmIdentity::Firecracker,
    );
    assert_eq!(
        refused,
        Err(SandboxError::AcceleratorUnsupported {
            vmm: VmmIdentity::Firecracker
        })
    );
    let admitted = MicroVmRequest::new(
        label(SANDBOX)?,
        GuestMemoryMib::new(GUEST_MIB)?,
        true,
        VmmIdentity::QemuMicrovm,
    )?;
    assert!(admitted.accelerator);
    assert_eq!(admitted.vmm, VmmIdentity::QemuMicrovm);
    assert_eq!(admitted.memory.get(), GUEST_MIB);
    assert_eq!(admitted.name, label(SANDBOX)?);
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the 64th sandbox is accepted and the 65th is refused.
#[test]
fn the_sixty_fifth_sandbox_is_refused() -> Fallible {
    let mut controller = filled_controller(MAX_MICROVMS.saturating_sub(1))?;
    assert_eq!(controller.count(), 63);
    controller.spawn(sandbox_request(VmmIdentity::Firecracker)?)?;
    assert_eq!(controller.count(), MAX_MICROVMS);
    let refused = controller.spawn(sandbox_request(VmmIdentity::Firecracker)?);
    assert_eq!(refused, Err(SandboxError::MicroVmTableFull { max: 64 }));
    assert_eq!(
        controller.count(),
        MAX_MICROVMS,
        "the refusal stores nothing"
    );
    Ok(())
}

/// Boundary: identifiers and context identifiers count up from the recorded
/// first values, and the last sandbox is still inside the `vsock` range.
#[test]
fn identifiers_count_up_from_the_recorded_first_values() -> Fallible {
    let controller = filled_controller(MAX_MICROVMS)?;
    let last = u32::try_from(MAX_MICROVMS.saturating_sub(1)).unwrap_or(u32::MAX);
    let first = controller
        .get(VmId::new(FIRST_VM_ID))
        .ok_or("the first sandbox must be readable")?;
    let final_row = controller
        .get(VmId::new(FIRST_VM_ID.saturating_add(last)))
        .ok_or("the last sandbox must be readable")?;
    assert_eq!(first.vm_id.get(), FIRST_VM_ID);
    assert_eq!(final_row.vm_id.get(), FIRST_VM_ID.saturating_add(last));
    assert!(final_row.vsock_cid.get() > first.vsock_cid.get());
    assert!(first.vsock_cid.get() >= FIRST_GUEST_CID);
    assert!(
        controller
            .get(VmId::new(
                FIRST_VM_ID.saturating_add(last).saturating_add(1)
            ))
            .is_none()
    );
    Ok(())
}
