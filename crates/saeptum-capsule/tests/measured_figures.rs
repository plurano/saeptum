// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Measured figures name their monitor; targets stay unmeasured.
//!
//! Positive: the boot time and footprint are [`Measured`] values naming
//! Firecracker and the run behind them, the two targets are [`Unmeasured`]
//! values, and a Firecracker sandbox row carries the measured boot time.
//! Negative: a `QEMU` microvm row carries no boot time rather than
//! Firecracker's (D58), and no value this crate serialises carries a figure.
//! Boundary: both measured figures miss the REQ-P10-01 targets they are held
//! against, which is a statement about one recorded run, not about every
//! sandbox.
//!
//! The compile-time half lives in `src/measured.rs`: its `compile_fail`
//! doctests show that a bare number, or a figure naming no monitor, does not
//! build.

mod common;

use saeptum_capsule::{
    BOOT_TIME_TARGET_MS, FOOTPRINT_TARGET_MIB, MEASURED_BOOT_TIME_MS, MEASURED_FOOTPRINT_KIB,
    Measured, Unmeasured, VmId, VmmIdentity,
};

use common::{Fallible, sandbox_request};

/// The run of `make verify-workstation` that produced both figures.
const RUN: &str = "r20261017T124857-0027";

/// Accepts only a value that names the monitor and run behind it.
fn assert_measured<T: Copy>(_value: Measured<T>) {}

/// Accepts only a value that says it was never measured.
fn assert_unmeasured<T: Copy>(_value: Unmeasured<T>) {}

// --- Positive -------------------------------------------------------------

/// Positive: the boot time and footprint are measured on Firecracker in the
/// named run.
///
/// This is the falsifier. Changing either constant to a bare integer, or to
/// an [`Unmeasured`] value, stops this file compiling, which fails the gate.
#[test]
fn the_figures_are_measured_on_firecracker() {
    assert_measured(MEASURED_BOOT_TIME_MS);
    assert_measured(MEASURED_FOOTPRINT_KIB);
    for (figure, value) in [
        (MEASURED_BOOT_TIME_MS, 306),
        (MEASURED_FOOTPRINT_KIB, 61_620),
    ] {
        assert_eq!(figure.get(), value);
        assert_eq!(figure.vmm(), VmmIdentity::Firecracker);
        assert_eq!(figure.run(), RUN);
    }
}

/// Positive: the targets stay unmeasured values.
#[test]
fn the_targets_stay_unmeasured() {
    assert_unmeasured(BOOT_TIME_TARGET_MS);
    assert_unmeasured(FOOTPRINT_TARGET_MIB);
    assert_eq!(BOOT_TIME_TARGET_MS.get(), 125);
    assert_eq!(FOOTPRINT_TARGET_MIB.get(), 5);
    assert_eq!(BOOT_TIME_TARGET_MS.to_string(), "125 (unmeasured)");
    assert_eq!(Unmeasured::new(0u32).to_string(), "0 (unmeasured)");
}

/// Positive: a measured figure renders its monitor, version and run next to
/// the number, so a figure copied into a report carries its provenance.
#[test]
fn a_measured_figure_renders_its_provenance() {
    assert_eq!(
        MEASURED_BOOT_TIME_MS.to_string(),
        "306 (measured on firecracker 1.17.0, run r20261017T124857-0027)"
    );
    assert_eq!(
        Measured::new(7u32, VmmIdentity::QemuMicrovm, "r0").to_string(),
        "7 (measured on qemu-microvm 11.1.1, run r0)"
    );
}

/// Positive: every Firecracker sandbox row carries the measured boot time.
#[test]
fn every_firecracker_row_carries_the_measured_boot_time() -> Fallible {
    let controller = common::filled_controller(3)?;
    for raw in [100u32, 101, 102] {
        let row = controller
            .get(VmId::new(raw))
            .ok_or("the table must hold the sandbox")?;
        assert_eq!(row.measured_boot_time_ms, Some(MEASURED_BOOT_TIME_MS));
    }
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a `QEMU` microvm row carries no boot time, because none was
/// measured on that monitor and Firecracker's is not interchangeable (D58).
#[test]
fn a_qemu_row_borrows_no_firecracker_figure() -> Fallible {
    let mut controller = saeptum_capsule::MicroVmController::new();
    let id = controller.spawn(sandbox_request(VmmIdentity::QemuMicrovm)?)?;
    let row = controller
        .get(id)
        .ok_or("the table must hold the sandbox")?;
    assert_eq!(row.measured_boot_time_ms, None);
    assert_eq!(
        MEASURED_BOOT_TIME_MS.for_vmm(VmmIdentity::QemuMicrovm),
        None
    );
    assert_eq!(
        MEASURED_FOOTPRINT_KIB.for_vmm(VmmIdentity::Firecracker),
        Some(MEASURED_FOOTPRINT_KIB)
    );
    Ok(())
}

/// Negative: no serialisable value carries a figure, so a consumer gets one
/// only through the typed constants and their provenance.
#[test]
fn no_serialised_value_carries_a_figure() -> Fallible {
    let vmm = serde_json::to_string(&VmmIdentity::Firecracker)?;
    let vm = serde_json::to_string(&VmId::new(100))?;
    for payload in [&vmm, &vm] {
        for field in ["boot", "306", "61620", "footprint", "latency", "measured"] {
            assert!(
                !payload.contains(field),
                "no serialised value may carry {field}: {payload}"
            );
        }
    }
    assert_eq!(vmm, "\"firecracker\"");
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the measured boot time misses its target, by 181 ms in this run.
#[test]
fn the_boot_time_misses_its_target() {
    assert!(MEASURED_BOOT_TIME_MS.get() > BOOT_TIME_TARGET_MS.get());
    assert_eq!(
        MEASURED_BOOT_TIME_MS
            .get()
            .saturating_sub(BOOT_TIME_TARGET_MS.get()),
        181,
        "the run's median boot time over the REQ-P10-01 target"
    );
}

/// Boundary: the measured footprint misses its target. The target is in
/// mebibytes and the figure in kibibytes, so the comparison converts once.
#[test]
fn the_footprint_misses_its_target() {
    let target_kib = FOOTPRINT_TARGET_MIB.get().saturating_mul(1024);
    assert_eq!(target_kib, 5120);
    assert!(MEASURED_FOOTPRINT_KIB.get() > target_kib);
}
