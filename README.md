<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

# Saeptum

Saeptum is one Rust library for running a job inside a bounded sandbox, with a
Go binding for Go programs. It brings three sandbox implementations that exist
today in separate repositories under one interface:

- the microVM and WebAssembly capsule controllers of the Aegis OS crates
  `aegis-vesta` and `aegis-vesta-sandbox` (Firecracker microVMs on KVM);
- the sandboxed job runner of Epitrop (`internal/supervisor/sandbox_linux.go`,
  bubblewrap and systemd-run);
- the agent sandbox planned for the Kubernetes cluster.

Each of those keeps its own copy until this library ships a release that covers
it; the copy is then replaced by a dependency on that release.

## The name

*Saeptum* is Latin for an enclosure or a fenced pen (from *saepire*, to fence
in). It is pronounced SYEP-tum in classical Latin, SEP-tum in church Latin.

## Status

No code yet. The repository stays private until its first release.

## Licence

Licensed under the European Union Public Licence 1.2
([LICENSES/EUPL-1.2.txt](LICENSES/EUPL-1.2.txt)). The repository follows the
[REUSE](https://reuse.software) specification.
