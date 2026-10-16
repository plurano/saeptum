// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! Which virtual machine monitor a sandbox names (decision D58).
//!
//! D58 selects Firecracker as the sandbox virtual machine monitor for P10 and
//! keeps `QEMU` with the `microvm` machine type as the recorded fallback, and it
//! attaches a rule to both: **every measurement records which monitor produced
//! it, and the two sets are never presented as interchangeable.** A boot time
//! or a footprint without a monitor beside it is not a comparable number.
//!
//! That rule is why [`VmmIdentity`] is a field of the capsule request rather
//! than a build-time constant. Nothing here starts a monitor, and nothing here
//! measures anything, so the identity travels with the request and the register
//! below records what was found on one host on one day.
//!
//! # What [`VMM_PROBES`] is
//!
//! A register of two probes run by hand at milestone M06 on the reference
//! profile, each with the command that produced it and the string that came
//! back. It is **not** a capability check: no test re-runs these commands, this
//! crate executes no command at all, and a host that has neither monitor
//! installed passes every test in this crate. Read it as a dated note about one
//! machine, and re-run the commands if the answer matters.
//!
//! Both probes contradict one sentence in the recorded roadmap, which describes
//! Firecracker as packaged but absent. On the profile measured here it is
//! installed, which is also what `planning/hardware-profile.json` records.

/// The monitors a P10 sandbox may name.
///
/// Two variants, because D58 admits two: the chosen monitor and the recorded
/// fallback. Neither is a default here -- a payload names one explicitly, so a
/// number carried alongside it can never be attributed to the wrong monitor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum VmmIdentity {
    /// Firecracker, the monitor D58 chose for P10 and M22.
    Firecracker,
    /// `QEMU` with the `microvm` machine type, the recorded fallback.
    QemuMicrovm,
}

impl VmmIdentity {
    /// Both monitors D58 names, in the order the decision lists them.
    pub const BOTH: [Self; 2] = [Self::Firecracker, Self::QemuMicrovm];

    /// The monitor decision D58 chose.
    pub const CHOSEN: Self = Self::Firecracker;

    /// Returns the stable tag the wire form carries.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Firecracker => "firecracker",
            Self::QemuMicrovm => "qemu-microvm",
        }
    }

    /// Returns the version D58 pins for this monitor.
    ///
    /// A pin is not an admission: `docs/roadmap/toolchain-admission.md` records
    /// which tool a gate runs. M21 admits Firecracker at this version, fetched
    /// and pinned by digest for `make verify-workstation`; QEMU at this version
    /// is admitted for the guest gates of M26, M23, M24 and M10 and runs no
    /// sandbox.
    #[must_use]
    pub const fn pinned_version(self) -> &'static str {
        match self {
            Self::Firecracker => "1.17.0",
            Self::QemuMicrovm => "11.1.1",
        }
    }

    /// Returns `true` when this monitor can pass a `PCI` device through.
    ///
    /// The asymmetry is the second fact D58 rests on: Firecracker has no `PCI`
    /// passthrough, so a sandbox that asks for an accelerator cannot use it.
    /// [`MicroVmRequest`](crate::MicroVmRequest) is where that becomes a
    /// refusal rather than a footnote.
    #[must_use]
    pub const fn supports_pci_passthrough(self) -> bool {
        match self {
            Self::Firecracker => false,
            Self::QemuMicrovm => true,
        }
    }
}

/// One monitor probe, run by hand and recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VmmProbe {
    /// The monitor the probe was about.
    pub vmm: VmmIdentity,
    /// The command that was run.
    pub command: &'static str,
    /// What the command printed, verbatim.
    pub observed: &'static str,
    /// The distribution package the binary came from.
    pub package: &'static str,
    /// The day the probe was run.
    pub probed_on: &'static str,
}

/// The two probes run on the reference profile at milestone M06.
///
/// Recorded, not re-run: this crate executes no command, so these are evidence
/// about one host on one day and about nothing else.
pub const VMM_PROBES: [VmmProbe; 2] = [
    VmmProbe {
        vmm: VmmIdentity::Firecracker,
        command: "firecracker --version",
        observed: "Firecracker v1.17.0",
        package: "firecracker 1.17.0-1.1",
        probed_on: "2026-09-13",
    },
    VmmProbe {
        vmm: VmmIdentity::QemuMicrovm,
        command: "qemu-system-x86_64 --version",
        observed: "QEMU emulator version 11.1.1",
        package: "qemu-system-x86 11.1.1-2",
        probed_on: "2026-09-13",
    },
];
