// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! `saeptum-microvm`: the half of the Saeptum sandbox library that starts
//! something, on real KVM, and starts nothing `saeptum-capsule` did not admit.
//!
//! The code moved here from Aegis OS `aegis-vesta-sandbox` (placement
//! CUT-1632-04, which also homes the job sandbox of CUT-1632-02). What stays
//! in Aegis is what a request means: its candidate-evaluation request and
//! answer, the Pareto gate the guest judges with, the reference run and the
//! two binaries. Aegis adapts those to this crate at its boundary.
//!
//! # Identifiers in this documentation
//!
//! Comments here cite the Aegis OS record the code was written against:
//! `D58`, `D71` and the like are its decision records, `M21` and the like its
//! milestones, and `HISS-02` its rule that every loop and every wait carries
//! a bound. They are provenance, not dependencies: nothing in this crate reads
//! them, and the crate builds without the Aegis OS repository.
//!
//! # The things a reviewer should look at
//!
//! * [`RunningVm::start`] boots a row of a [`saeptum_capsule::MicroVmController`]
//!   with the caller's Firecracker binary (Aegis pins 1.17.0 under D58) from a
//!   per-VM configuration file ([`config`]) with `--no-api`, no drive, no
//!   network interface and one vsock device whose guest context identifier is
//!   the one the controller derived.
//! * [`RunningVm::exchange`] sends one line to a guest port and returns one
//!   line, bounded in bytes and in time; [`RunningVm::stop`] (or dropping the
//!   value) kills, reaps and removes the sockets.
//! * [`serve`] is the guest's bounded service on `AF_VSOCK`; [`answer`] frames
//!   one request and one answer for any [`Responder`].
//! * [`mod@line`] frames both directions and Firecracker's hybrid-vsock
//!   handshake: the host end is `AF_UNIX`, the guest end `AF_VSOCK`, and
//!   Firecracker's own device model carries the bytes between them (its
//!   `docs/vsock.md`).
//!
//! # What this crate does not claim
//!
//! It fetches no Firecracker binary, kernel or initramfs: the caller names
//! them in [`Launch`]. It measures no boot time and no memory footprint, uses
//! no jailer, and runs every microVM as the invoking user. A pass of its tests
//! is development evidence and closes no hardware, isolation or release gate.

pub mod config;
pub mod error;
pub mod guest;
pub mod line;
pub mod vm;

pub use crate::config::{
    BOOT_ARGS, MAX_SOCKET_PATH_BYTES, VCPU_COUNT, VmConfig, check_socket_path, render,
};
pub use crate::error::MicroVmError;
pub use crate::guest::{
    ACCEPT_BUDGET, BACKLOG, GUEST_EXCHANGE_BUDGET, MAX_GUEST_CONNECTIONS, Responder, Service,
    VMADDR_CID_ANY, answer, serve,
};
pub use crate::line::{
    MAX_ACK_BYTES, Unframed, connect_command, deadline_error, parse_ack, read_line, timed_out,
};
pub use crate::vm::{
    BOOT_BUDGET, EXCHANGE_BUDGET, HANDSHAKE_BUDGET, Launch, MAX_DIRECTORY_ENTRIES, MAX_POLLS, POLL,
    RunningVm, SOCKET_NAME, STOP_BUDGET, Stopped,
};
