// SPDX-FileCopyrightText: 2026 Lusoris <lusoris@proton.me>
// SPDX-License-Identifier: EUPL-1.2

//! The opt-in launch switches and the process id of a started microVM.
//!
//! A shell stand-in takes Firecracker's place and records its own process id
//! and its arguments, one per line, in the microVM's directory, so the test
//! reads the exact command line `RunningVm::start_with` built.
//!
//! Positive: the boot timer switched on adds `--boot-timer`, and `pid` names
//! the process the stand-in runs as. Negative: `start` and the default
//! options pass no `--boot-timer`. Boundary: switching the boot timer on and
//! off again is the default, and the switch adds exactly one argument after
//! the fixed five.

mod common;

use std::path::Path;
use std::time::{Duration, Instant};

use saeptum_microvm::{Launch, LaunchOptions, MAX_POLLS, POLL, RunningVm};

use common::{Fallible, admitted, scratch, spawn_lock, stand_in};

/// Writes the process id and every argument, then stays up until killed.
const RECORDS_ARGUMENTS: &str =
    "printf '%s\\n' \"$$\" \"$@\" > argv.part && mv argv.part argv && exec sleep 30";

/// How long the stand-in has to write its record.
const RECORD_BUDGET: Duration = Duration::from_secs(10);

/// The arguments every launch passes before any switch.
const FIXED_ARGUMENTS: usize = 5;

/// Starts the admitted row under `run_dir` with `options` or, for `None`,
/// with [`RunningVm::start`].
fn start(
    run_dir: &Path,
    options: Option<LaunchOptions>,
) -> Result<RunningVm, Box<dyn std::error::Error>> {
    let _guard = spawn_lock()?;
    let firecracker = stand_in(run_dir, RECORDS_ARGUMENTS)?;
    let launch = Launch {
        firecracker: &firecracker,
        kernel: Path::new("/cache/vmlinux"),
        initrd: Path::new("/cache/initramfs.cpio"),
        run_dir,
    };
    let instance = admitted()?;
    Ok(match options {
        Some(options) => RunningVm::start_with(&launch, &instance, options)?,
        None => RunningVm::start(&launch, &instance)?,
    })
}

/// Waits for the stand-in's record and returns its process id and arguments.
fn record(vm: &RunningVm) -> Result<(u32, Vec<String>), Box<dyn std::error::Error>> {
    let path = vm.dir().join("argv");
    let started = Instant::now();
    for _ in 0..MAX_POLLS {
        if let Ok(text) = std::fs::read_to_string(&path) {
            let mut lines = text.lines().map(str::to_owned);
            let pid = lines.next().ok_or("the record is empty")?.parse()?;
            return Ok((pid, lines.collect()));
        }
        if started.elapsed() > RECORD_BUDGET {
            break;
        }
        std::thread::sleep(POLL);
    }
    Err("the stand-in wrote no record".into())
}

/// Starts with `options`, returns the recorded arguments, and cleans up.
fn arguments(
    name: &str,
    options: Option<LaunchOptions>,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let dir = scratch(name)?;
    let vm = start(&dir, options)?;
    let (_, arguments) = record(&vm)?;
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(arguments)
}

// --- Positive -------------------------------------------------------------

/// Positive: the boot timer switched on reaches Firecracker's command line.
#[test]
fn the_boot_timer_adds_its_flag() -> Fallible {
    let on = LaunchOptions::default().with_boot_timer(true);
    assert!(on.boot_timer);
    let arguments = arguments("boot-timer-on", Some(on))?;
    assert!(arguments.iter().any(|argument| argument == "--boot-timer"));
    Ok(())
}

/// Positive: `pid` is the process the stand-in runs as.
#[test]
fn pid_names_the_started_process() -> Fallible {
    let dir = scratch("pid")?;
    let vm = start(&dir, None)?;
    let (recorded, _) = record(&vm)?;
    assert_eq!(vm.pid(), recorded);
    assert!(Path::new(&format!("/proc/{}", vm.pid())).exists());
    vm.stop()?;
    std::fs::remove_dir_all(dir)?;
    Ok(())
}

// --- Negative -------------------------------------------------------------

/// Negative: `start` and the default options leave the boot timer out.
#[test]
fn the_default_passes_no_boot_timer() -> Fallible {
    assert!(!LaunchOptions::default().boot_timer);
    for (name, options) in [("plain", None), ("default", Some(LaunchOptions::default()))] {
        let arguments = arguments(name, options)?;
        assert!(!arguments.iter().any(|argument| argument == "--boot-timer"));
        assert_eq!(arguments.first().map(String::as_str), Some("--no-api"));
    }
    Ok(())
}

// --- Boundary -------------------------------------------------------------

/// Boundary: on then off is the default, and on adds one argument at the end.
#[test]
fn the_switch_adds_exactly_one_trailing_argument() -> Fallible {
    let toggled = LaunchOptions::default()
        .with_boot_timer(true)
        .with_boot_timer(false);
    assert_eq!(toggled, LaunchOptions::default());
    let off = arguments("toggled", Some(toggled))?;
    assert_eq!(off.len(), FIXED_ARGUMENTS);
    let on = arguments(
        "trailing",
        Some(LaunchOptions::default().with_boot_timer(true)),
    )?;
    assert_eq!(on.len(), FIXED_ARGUMENTS + 1);
    // Index 2 is the configuration path, which names each run's own directory.
    for index in [0, 1, 3, 4] {
        assert_eq!(on.get(index), off.get(index));
    }
    assert_eq!(on.last().map(String::as_str), Some("--boot-timer"));
    Ok(())
}
