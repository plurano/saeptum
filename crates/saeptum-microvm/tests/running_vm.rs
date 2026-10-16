// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! One microVM process: started, reached, stopped.
//!
//! Firecracker is not run here. A shell stand-in takes its place as the
//! process, and the test binds the hybrid-vsock Unix socket itself and speaks
//! Firecracker's side of the handshake (`docs/vsock.md`, v1.17.0), so the
//! host half runs end to end over a real socket.
//!
//! Positive: a started row writes the controller's memory and context
//! identifier into its configuration, one exchange round-trips, and stopping
//! reaps the process and removes the socket. Negative: a guest `ERROR`
//! answer, a request with a newline, a process that exits before its guest
//! accepts, a missing binary and an occupied directory are each refused.
//! Boundary: an answer of exactly its bound is read and one byte more is
//! refused; a socket path of exactly the `AF_UNIX` limit starts and one byte
//! more is refused before any directory is created; a process that already
//! exited is still reaped with its own status.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;

use saeptum_microvm::{
    Launch, MAX_SOCKET_PATH_BYTES, MicroVmError, RunningVm, SOCKET_NAME, connect_command,
};
use serde_json::Value;

use common::{
    EXITS_AT_ONCE, FIRST_CID, FIRST_VM, Fallible, PORT, STAYS_UP, admitted, scratch, spawn_lock,
    stand_in,
};

/// Starts the admitted row with a stand-in running `body` under `run_dir`.
fn start(run_dir: &Path, body: &str) -> Result<RunningVm, Box<dyn std::error::Error>> {
    let _guard = spawn_lock()?;
    let firecracker = stand_in(run_dir, body)?;
    let launch = Launch {
        firecracker: &firecracker,
        kernel: Path::new("/cache/vmlinux"),
        initrd: Path::new("/cache/initramfs.cpio"),
        run_dir,
    };
    Ok(RunningVm::start(&launch, &admitted()?)?)
}

/// Plays Firecracker's side: acknowledges one `CONNECT`, then answers the
/// request line with `answer`. Returns what the guest was asked.
fn fake_device(socket: &Path, answer: String) -> std::io::Result<JoinHandle<String>> {
    let listener = UnixListener::bind(socket)?;
    Ok(std::thread::spawn(move || {
        let Ok((stream, _)) = listener.accept() else {
            return String::new();
        };
        let mut reader = BufReader::new(&stream);
        let mut connect = String::new();
        let mut request = String::new();
        let mut writer = &stream;
        let _ = reader.read_line(&mut connect);
        if connect != connect_command(PORT) {
            return format!("unexpected handshake {connect:?}");
        }
        let _ = writer.write_all(b"OK 1073741825\n");
        let _ = reader.read_line(&mut request);
        let _ = writer.write_all(answer.as_bytes());
        request
    }))
}

/// A run directory whose socket path is exactly `length` bytes long.
fn run_dir_for_socket(base: &Path, length: usize) -> PathBuf {
    let tail = format!("/vm-{FIRST_VM}/{SOCKET_NAME}").len();
    let used = base
        .as_os_str()
        .len()
        .saturating_add(1)
        .saturating_add(tail);
    base.join("d".repeat(length.saturating_sub(used).max(1)))
}

// --- Positive -------------------------------------------------------------

/// Positive: the configuration carries the controller's row.
#[test]
fn a_started_row_carries_the_controllers_values() -> Fallible {
    let dir = scratch("config")?;
    let mut vm = start(&dir, STAYS_UP)?;
    assert_eq!(vm.cid().get(), FIRST_CID);
    assert_eq!(vm.vm_id().get(), FIRST_VM);
    assert!(vm.alive()?);
    let config: Value = serde_json::from_str(&std::fs::read_to_string(vm.dir().join("vm.json"))?)?;
    assert_eq!(
        config.pointer("/vsock/guest_cid").and_then(Value::as_u64),
        Some(u64::from(FIRST_CID))
    );
    assert_eq!(
        config
            .pointer("/machine-config/mem_size_mib")
            .and_then(Value::as_u64),
        Some(64)
    );
    let stopped = vm.stop()?;
    assert_eq!(stopped.vm_id.get(), FIRST_VM);
    assert_eq!(stopped.sockets_removed, 0);
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Positive: one exchange round-trips and stopping removes the socket.
#[test]
fn one_exchange_round_trips_and_stop_cleans_up() -> Fallible {
    let dir = scratch("exchange")?;
    let mut vm = start(&dir, STAYS_UP)?;
    let device = fake_device(vm.socket(), "verdict accepted\n".to_owned())?;
    let answer = vm.exchange(PORT, "evaluate candidate 7", 64)?;
    assert_eq!(answer, "verdict accepted");
    let asked = device.join().map_err(|_| "the fake device panicked")?;
    assert_eq!(asked, "evaluate candidate 7\n");
    let stopped = vm.stop()?;
    assert_eq!(stopped.sockets_removed, 1);
    assert!(
        !dir.join(format!("vm-{FIRST_VM}"))
            .join(SOCKET_NAME)
            .exists()
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: a guest refusal is reported with its reason.
#[test]
fn a_guest_error_answer_is_a_refusal() -> Fallible {
    let dir = scratch("refusal")?;
    let mut vm = start(&dir, STAYS_UP)?;
    let _device = fake_device(vm.socket(), "ERROR not this sandbox\n".to_owned())?;
    let outcome = vm.exchange(PORT, "evaluate", 64);
    assert!(
        matches!(&outcome, Err(MicroVmError::Refused(reason)) if reason == "the guest refused: not this sandbox"),
        "{outcome:?}"
    );
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: a request carrying a newline is refused before any connection.
#[test]
fn a_request_with_a_newline_is_refused() -> Fallible {
    let dir = scratch("newline")?;
    let mut vm = start(&dir, STAYS_UP)?;
    assert!(matches!(
        vm.exchange(PORT, "one\ntwo", 64),
        Err(MicroVmError::Protocol(_))
    ));
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: a process that exits before its guest accepts is reported.
#[test]
fn an_exited_process_is_refused() -> Fallible {
    let dir = scratch("exited")?;
    let mut vm = start(&dir, EXITS_AT_ONCE)?;
    let outcome = vm.exchange(PORT, "evaluate", 64);
    assert!(
        matches!(&outcome, Err(MicroVmError::Refused(reason)) if reason.contains("exited before its guest accepted")),
        "{outcome:?}"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: a missing binary and an occupied directory are I/O refusals.
#[test]
fn a_missing_binary_or_occupied_directory_is_refused() -> Fallible {
    let dir = scratch("missing")?;
    let instance = admitted()?;
    let missing = dir.join("no-such-firecracker");
    let launch = Launch {
        firecracker: &missing,
        kernel: Path::new("/cache/vmlinux"),
        initrd: Path::new("/cache/initramfs.cpio"),
        run_dir: &dir,
    };
    let first = RunningVm::start(&launch, &instance);
    assert!(
        matches!(
            &first,
            Err(MicroVmError::Io {
                what: "starting firecracker",
                ..
            })
        ),
        "{first:?}"
    );
    let second = RunningVm::start(&launch, &instance);
    assert!(
        matches!(
            &second,
            Err(MicroVmError::Io {
                what: "creating a microVM directory",
                ..
            })
        ),
        "{second:?}"
    );
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: a socket path that cannot be connected for a reason other than
/// "not there yet" fails the handshake with an I/O error, not a retry.
#[test]
fn an_unusable_socket_path_is_an_io_refusal() -> Fallible {
    let dir = scratch("unusable")?;
    let mut vm = start(&dir, STAYS_UP)?;
    // A symbolic link to itself: connect fails with ELOOP, also as root.
    std::os::unix::fs::symlink(vm.socket(), vm.socket())?;
    let outcome = vm.exchange(PORT, "evaluate", 64);
    assert!(
        matches!(
            outcome,
            Err(MicroVmError::Io {
                what: "connecting to the vsock socket",
                ..
            })
        ),
        "{outcome:?}"
    );
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: dropping a running VM without stopping terminates its process.
#[test]
fn dropping_a_running_vm_terminates_its_process() -> Fallible {
    let dir = scratch("drop")?;
    let vm = start(&dir, "echo $$; exec sleep 30")?;
    let console_path = vm.dir().join("console.log");
    let mut pid = String::new();
    for _ in 0..1_000 {
        pid = std::fs::read_to_string(&console_path).unwrap_or_default();
        if !pid.trim().is_empty() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    let pid = pid.trim();
    assert_ne!(pid, "");
    let proc_path = format!("/proc/{pid}");
    assert!(std::path::Path::new(&proc_path).exists());
    drop(vm);
    assert!(!std::path::Path::new(&proc_path).exists());
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Negative: a silent device misses the handshake deadline.
#[test]
fn a_silent_device_times_out_the_handshake() -> Fallible {
    let dir = scratch("silent")?;
    let mut vm = start(&dir, STAYS_UP)?;
    let listener = UnixListener::bind(vm.socket())?;
    let _device = std::thread::spawn(move || {
        let Ok((_stream, _)) = listener.accept() else {
            return;
        };
        std::thread::sleep(std::time::Duration::from_millis(3_000));
    });
    let outcome = vm.exchange(PORT, "evaluate", 64);
    assert!(
        matches!(
            outcome,
            Err(MicroVmError::Deadline {
                what: "the vsock handshake",
                millis: 1000,
            })
        ),
        "{outcome:?}"
    );
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: an answer of exactly its bound is read; one byte more is not.
#[test]
fn the_answer_bound_is_closed_at_its_edge() -> Fallible {
    let dir = scratch("bound")?;
    let mut vm = start(&dir, STAYS_UP)?;
    let exact = format!("{}\n", "a".repeat(15));
    let _device = fake_device(vm.socket(), exact)?;
    assert_eq!(vm.exchange(PORT, "evaluate", 16)?, "a".repeat(15));
    std::fs::remove_file(vm.socket())?;
    let _device = fake_device(vm.socket(), format!("{}\n", "a".repeat(16)))?;
    assert!(matches!(
        vm.exchange(PORT, "evaluate", 16),
        Err(MicroVmError::Protocol(_))
    ));
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

/// Boundary: the socket path limit is checked before a directory exists.
#[test]
fn the_socket_path_limit_is_closed_at_its_edge() -> Fallible {
    let base = scratch("path")?;
    let at_limit = run_dir_for_socket(&base, MAX_SOCKET_PATH_BYTES);
    std::fs::create_dir_all(&at_limit)?;
    let vm = start(&at_limit, STAYS_UP)?;
    assert_eq!(vm.socket().as_os_str().len(), MAX_SOCKET_PATH_BYTES);
    vm.stop()?;
    let past = run_dir_for_socket(&base, MAX_SOCKET_PATH_BYTES.saturating_add(1));
    std::fs::create_dir_all(&past)?;
    let outcome = start(&past, STAYS_UP);
    assert!(outcome.is_err());
    assert!(!past.join(format!("vm-{FIRST_VM}")).exists());
    std::fs::remove_dir_all(base)?;
    Ok(())
}

/// Boundary: a process that already exited is reaped with its own status.
#[test]
fn an_exited_process_is_reaped_with_its_status() -> Fallible {
    let dir = scratch("reaped")?;
    let mut vm = start(&dir, EXITS_AT_ONCE)?;
    for _ in 0..500 {
        if !vm.alive()? {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let stopped = vm.stop()?;
    assert_eq!(stopped.status.code(), Some(3));
    std::fs::remove_dir_all(dir)?;
    Ok(())
}
