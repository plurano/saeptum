// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! One Firecracker process on the host: started, reached, stopped.
//!
//! A [`RunningVm`] exists only for a row a
//! [`saeptum_capsule::MicroVmController`] admitted: [`RunningVm::start`]
//! takes the controller's [`MicroVmInstance`], so the context identifier the
//! guest holds is the one the controller derived, and a request the
//! controller refused never reaches a process. Every wait is bounded twice,
//! by a poll count and by a budget (HISS-02), and a [`RunningVm`] that is
//! dropped without [`RunningVm::stop`] still kills and reaps its process.
//!
//! What travels over the connection is the caller's: [`RunningVm::exchange`]
//! sends one line and returns one line, and a guest that answers
//! `ERROR <reason>` (what [`crate::guest::answer`] writes for a refusal) is
//! reported as [`MicroVmError::Refused`].

use std::fs::{self, File};
use std::io::{ErrorKind, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use saeptum_capsule::{MicroVmInstance, VmId, VsockCid};

use crate::config::{VmConfig, check_socket_path, render};
use crate::error::MicroVmError;
use crate::line::{MAX_ACK_BYTES, Unframed, connect_command, deadline_error, parse_ack, read_line};

/// How long a microVM has from its process start to its guest accepting.
pub const BOOT_BUDGET: Duration = Duration::from_secs(10);

/// How long one handshake read may take.
pub const HANDSHAKE_BUDGET: Duration = Duration::from_secs(1);

/// How long one request and its answer may take.
pub const EXCHANGE_BUDGET: Duration = Duration::from_secs(5);

/// How long a killed process has to be reaped.
pub const STOP_BUDGET: Duration = Duration::from_secs(5);

/// The pause between two polls of a process or a socket.
pub const POLL: Duration = Duration::from_millis(10);

/// Scalar upper bound on the polls of one wait: 10 s at 10 ms.
pub const MAX_POLLS: u32 = 1_000;

/// Scalar upper bound on the entries a microVM directory is swept for sockets.
pub const MAX_DIRECTORY_ENTRIES: usize = 64;

/// The name of the host-side vsock socket inside a microVM's directory.
pub const SOCKET_NAME: &str = "v.sock";

/// What every microVM of one run is started from.
#[derive(Debug, Clone, Copy)]
pub struct Launch<'a> {
    /// The fetched, pinned Firecracker binary.
    pub firecracker: &'a Path,
    /// The pinned guest kernel.
    pub kernel: &'a Path,
    /// The initramfs holding the guest init.
    pub initrd: &'a Path,
    /// The run directory each microVM gets a subdirectory of.
    pub run_dir: &'a Path,
}

/// Opt-in switches for one microVM's process; every switch is off by default.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct LaunchOptions {
    /// Starts Firecracker with `--boot-timer`. Firecracker 1.17.0 then logs
    /// `Guest-boot-time = ...` to its stdout, the microVM's `console.log`,
    /// once the guest writes the boot-complete byte to the boot timer device.
    pub boot_timer: bool,
}

impl LaunchOptions {
    /// Returns these options with the boot timer switched to `on`.
    #[must_use]
    pub const fn with_boot_timer(self, on: bool) -> Self {
        Self { boot_timer: on }
    }
}

/// How a microVM's process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stopped {
    /// The sandbox that was stopped.
    pub vm_id: VmId,
    /// The process's exit status, once reaped.
    pub status: ExitStatus,
    /// How many socket files were removed from its directory.
    pub sockets_removed: usize,
}

/// One started Firecracker process and the sandbox it runs.
#[derive(Debug)]
pub struct RunningVm {
    vm_id: VmId,
    cid: VsockCid,
    dir: PathBuf,
    socket: PathBuf,
    child: Child,
    reaped: bool,
    started: Instant,
}

impl RunningVm {
    /// Starts the microVM for the controller's row `instance` with every
    /// [`LaunchOptions`] switch off.
    ///
    /// # Errors
    ///
    /// As [`RunningVm::start_with`].
    pub fn start(launch: &Launch<'_>, instance: &MicroVmInstance) -> Result<Self, MicroVmError> {
        Self::start_with(launch, instance, LaunchOptions::default())
    }

    /// Starts the microVM for the controller's row `instance` with `options`.
    ///
    /// # Errors
    ///
    /// Returns [`MicroVmError::Io`] when the directory, the configuration or
    /// the console cannot be written or the process cannot be started, and
    /// [`MicroVmError::Refused`] for a path the configuration refuses; a
    /// refused socket path is caught before the directory is created.
    pub fn start_with(
        launch: &Launch<'_>,
        instance: &MicroVmInstance,
        options: LaunchOptions,
    ) -> Result<Self, MicroVmError> {
        let vm_id = instance.vm_id;
        let dir = launch.run_dir.join(format!("vm-{}", vm_id.get()));
        let socket = dir.join(SOCKET_NAME);
        check_socket_path(&socket)?;
        fs::create_dir(&dir)
            .map_err(|error| MicroVmError::io("creating a microVM directory", error))?;
        let config = render(&VmConfig {
            kernel: launch.kernel,
            initrd: launch.initrd,
            memory: instance.memory,
            cid: instance.vsock_cid,
            socket: &socket,
        })?;
        let config_path = dir.join("vm.json");
        fs::write(&config_path, config)
            .map_err(|error| MicroVmError::io("writing a microVM configuration", error))?;
        let child = spawn(launch.firecracker, &config_path, &dir, vm_id, options)?;
        Ok(Self {
            vm_id,
            cid: instance.vsock_cid,
            dir,
            socket,
            child,
            reaped: false,
            started: Instant::now(),
        })
    }

    /// Returns the sandbox this process runs.
    #[must_use]
    pub const fn vm_id(&self) -> VmId {
        self.vm_id
    }

    /// Returns the guest's context identifier.
    #[must_use]
    pub const fn cid(&self) -> VsockCid {
        self.cid
    }

    /// Returns the operating-system process id of the Firecracker process.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Returns the microVM's directory.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Returns the host-side vsock socket Firecracker listens on.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Returns `true` while the process has not exited.
    ///
    /// # Errors
    ///
    /// Returns [`MicroVmError::Io`] when the process cannot be polled.
    pub fn alive(&mut self) -> Result<bool, MicroVmError> {
        let polled = self
            .child
            .try_wait()
            .map_err(|error| MicroVmError::io("polling a firecracker process", error))?;
        Ok(polled.is_none())
    }

    /// Sends `request` to guest port `port` and returns the answer line,
    /// without its newline.
    ///
    /// `request` must not contain a newline: one message is one line.
    /// `max_answer_bytes` bounds the answer, its newline included.
    ///
    /// # Errors
    ///
    /// Returns [`MicroVmError`] when `request` carries a newline, the guest
    /// does not accept within [`BOOT_BUDGET`], the exchange passes
    /// [`EXCHANGE_BUDGET`] or `max_answer_bytes`, or the guest answers
    /// `ERROR <reason>`.
    pub fn exchange(
        &mut self,
        port: u32,
        request: &str,
        max_answer_bytes: usize,
    ) -> Result<String, MicroVmError> {
        if request.contains('\n') {
            return Err(MicroVmError::Protocol(
                "a request is one line and carries no newline".to_owned(),
            ));
        }
        let mut stream = self.connect(port)?;
        set_timeouts(&stream, EXCHANGE_BUDGET)?;
        stream
            .write_all(format!("{request}\n").as_bytes())
            .map_err(|error| MicroVmError::io("sending a request", error))?;
        let line = match read_line(&mut stream, max_answer_bytes, EXCHANGE_BUDGET, "the answer")? {
            Ok(line) => line,
            Err(Unframed::Closed(bytes)) => {
                return Err(MicroVmError::Protocol(format!(
                    "the guest closed the stream after {bytes} bytes of its answer"
                )));
            }
        };
        let body = line.trim_end_matches('\n');
        if let Some(reason) = body.strip_prefix("ERROR ") {
            return Err(MicroVmError::Refused(format!(
                "the guest refused: {reason}"
            )));
        }
        Ok(body.to_owned())
    }

    /// Connects to guest port `port` through the hybrid vsock.
    fn connect(&mut self, port: u32) -> Result<UnixStream, MicroVmError> {
        for _ in 0..MAX_POLLS {
            if self.started.elapsed() > BOOT_BUDGET {
                return Err(deadline_error(
                    "the guest accepting on its vsock port",
                    BOOT_BUDGET,
                ));
            }
            if !self.alive()? {
                return Err(MicroVmError::Refused(format!(
                    "firecracker for sandbox {} exited before its guest accepted; see {}",
                    self.vm_id.get(),
                    self.dir.join("console.log").display()
                )));
            }
            if let Some(stream) = self.handshake(port)? {
                return Ok(stream);
            }
            std::thread::sleep(POLL);
        }
        Err(deadline_error(
            "the guest accepting on its vsock port",
            BOOT_BUDGET,
        ))
    }

    /// One handshake attempt; `None` means "not listening yet".
    fn handshake(&self, port: u32) -> Result<Option<UnixStream>, MicroVmError> {
        let mut stream = match UnixStream::connect(&self.socket) {
            Ok(stream) => stream,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) =>
            {
                return Ok(None);
            }
            Err(error) => return Err(MicroVmError::io("connecting to the vsock socket", error)),
        };
        set_timeouts(&stream, HANDSHAKE_BUDGET)?;
        stream
            .write_all(connect_command(port).as_bytes())
            .map_err(|error| MicroVmError::io("sending the vsock connect command", error))?;
        match read_line(
            &mut stream,
            MAX_ACK_BYTES,
            HANDSHAKE_BUDGET,
            "the vsock handshake",
        )? {
            Ok(line) => {
                parse_ack(&line)?;
                Ok(Some(stream))
            }
            Err(Unframed::Closed(_)) => Ok(None),
        }
    }

    /// Kills the process, reaps it within [`STOP_BUDGET`] and removes its
    /// socket files.
    ///
    /// # Errors
    ///
    /// Returns [`MicroVmError::Deadline`] when the process is not reaped in
    /// time, and [`MicroVmError::Io`] when it cannot be signalled or a socket
    /// cannot be removed.
    pub fn stop(mut self) -> Result<Stopped, MicroVmError> {
        let status = self.reap()?;
        let sockets_removed = remove_sockets(&self.dir)?;
        Ok(Stopped {
            vm_id: self.vm_id,
            status,
            sockets_removed,
        })
    }

    /// Kills and reaps the process, bounded.
    fn reap(&mut self) -> Result<ExitStatus, MicroVmError> {
        match self.child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::InvalidInput => {}
            Err(error) => return Err(MicroVmError::io("killing a firecracker process", error)),
        }
        let started = Instant::now();
        for _ in 0..MAX_POLLS {
            let polled = self
                .child
                .try_wait()
                .map_err(|error| MicroVmError::io("reaping a firecracker process", error))?;
            if let Some(status) = polled {
                self.reaped = true;
                return Ok(status);
            }
            if started.elapsed() > STOP_BUDGET {
                break;
            }
            std::thread::sleep(POLL);
        }
        Err(deadline_error("reaping a firecracker process", STOP_BUDGET))
    }
}

impl Drop for RunningVm {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.reap();
        }
    }
}

/// Starts Firecracker with the configuration file and the switches `options`
/// turns on, nothing else.
fn spawn(
    firecracker: &Path,
    config: &Path,
    dir: &Path,
    vm_id: VmId,
    options: LaunchOptions,
) -> Result<Child, MicroVmError> {
    let console = File::create(dir.join("console.log"))
        .map_err(|error| MicroVmError::io("creating a console log", error))?;
    let errors = console
        .try_clone()
        .map_err(|error| MicroVmError::io("sharing a console log", error))?;
    let mut command = Command::new(firecracker);
    command
        .arg("--no-api")
        .arg("--config-file")
        .arg(config)
        .arg("--id")
        .arg(format!("saeptum-vm-{}", vm_id.get()));
    if options.boot_timer {
        command.arg("--boot-timer");
    }
    command
        .current_dir(dir)
        .stdin(Stdio::null())
        .stdout(console)
        .stderr(errors)
        .spawn()
        .map_err(|error| MicroVmError::io("starting firecracker", error))
}

/// Applies the same read and write timeout to `stream`.
fn set_timeouts(stream: &UnixStream, budget: Duration) -> Result<(), MicroVmError> {
    stream
        .set_read_timeout(Some(budget))
        .and_then(|()| stream.set_write_timeout(Some(budget)))
        .map_err(|error| MicroVmError::io("setting a socket timeout", error))
}

/// Removes every Unix socket file in `dir`, bounded, and returns the count.
fn remove_sockets(dir: &Path) -> Result<usize, MicroVmError> {
    use std::os::unix::fs::FileTypeExt;
    let entries = fs::read_dir(dir)
        .map_err(|error| MicroVmError::io("listing a microVM directory", error))?;
    let mut removed = 0_usize;
    for entry in entries.take(MAX_DIRECTORY_ENTRIES) {
        let entry =
            entry.map_err(|error| MicroVmError::io("listing a microVM directory", error))?;
        let kind = entry
            .file_type()
            .map_err(|error| MicroVmError::io("reading a file type", error))?;
        if kind.is_socket() {
            fs::remove_file(entry.path())
                .map_err(|error| MicroVmError::io("removing a vsock socket", error))?;
            removed = removed.saturating_add(1);
        }
    }
    Ok(removed)
}
