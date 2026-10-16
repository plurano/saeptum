// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The monitor register: which monitors a sandbox may name, and what the two
//! recorded probes returned.
//!
//! Positive: both probes are recorded with the command that produced them and
//! the version they reported. Negative: an unknown tag names no monitor, and
//! the chosen monitor cannot pass a device through. Boundary: the register's
//! arity is exactly two, so a monitor cannot be dropped without failing this
//! file.
//!
//! Nothing here runs a monitor. The register is static data.

use saeptum_capsule::{VMM_PROBES, VmmIdentity, VmmProbe};

// --- Positive -------------------------------------------------------------

/// Positive: both monitor probes are recorded with the command that produced
/// them, and Firecracker is the chosen one.
#[test]
fn the_monitor_probes_record_their_commands() {
    assert_eq!(VmmIdentity::CHOSEN, VmmIdentity::Firecracker);
    for probe in VMM_PROBES {
        let row: VmmProbe = probe;
        assert!(row.command.contains("--version"));
        assert_ne!(row.observed, "");
        assert!(row.package.contains(row.vmm.pinned_version()));
        assert_eq!(row.probed_on, "2026-09-13");
        assert!(
            row.observed.contains(row.vmm.pinned_version()),
            "the probe must report the pinned version"
        );
    }
}

/// Positive: both monitors have a distinct recorded tag and pinned version.
#[test]
fn both_monitors_have_a_distinct_tag() {
    assert_eq!(VmmIdentity::Firecracker.tag(), "firecracker");
    assert_eq!(VmmIdentity::QemuMicrovm.tag(), "qemu-microvm");
    assert_eq!(VmmIdentity::Firecracker.pinned_version(), "1.17.0");
    assert_eq!(VmmIdentity::QemuMicrovm.pinned_version(), "11.1.1");
}

// --- Negative -------------------------------------------------------------

/// Negative: the chosen monitor passes no device through, and an unknown
/// wire tag decodes to no monitor.
#[test]
fn the_chosen_monitor_passes_nothing_through() {
    assert!(!VmmIdentity::CHOSEN.supports_pci_passthrough());
    let unknown: Result<VmmIdentity, _> = serde_json::from_str("\"cloud-hypervisor\"");
    assert!(unknown.is_err());
}

// --- Boundary -------------------------------------------------------------

/// Boundary: the register holds exactly two monitors and two probes, and
/// exactly one monitor passes a device through.
#[test]
fn the_register_arity_is_exact() {
    assert_eq!(VmmIdentity::BOTH.len(), 2);
    assert_eq!(VMM_PROBES.len(), 2);
    let passthrough: Vec<VmmIdentity> = VmmIdentity::BOTH
        .into_iter()
        .filter(|vmm| vmm.supports_pci_passthrough())
        .collect();
    assert_eq!(passthrough, vec![VmmIdentity::QemuMicrovm]);
}
