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

<!-- praetor:readme-governance:start -->
[![HISS Adopted][praetor-hiss-badge]][praetor-hiss-agents]

Praetor manages this repository's declared governance policy. This managed
block records adoption state; it is not a verification certificate.

**Verification**: `make verify-all` runs the repository's configured
verification cascade.

**HISS Audit**: `praetorctl audit` enforces policy, generated-surface
integrity, and the debt ratchet.

**Context Sync**: `praetorctl compile-context --verify` verifies every
generated agent context against `AGENTS.md`.

**Debt Baseline**: `.standards-baseline.json` anchors the debt ratchet at
0 recorded infractions; audit forbids growth.

[praetor-hiss-badge]: https://img.shields.io/badge/Standards-HISS%20Adopted-blue
[praetor-hiss-agents]: https://github.com/plurano/saeptum/blob/HEAD/AGENTS.md
<!-- praetor:readme-governance:end -->
