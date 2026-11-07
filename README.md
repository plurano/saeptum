<!--
SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
SPDX-License-Identifier: EUPL-1.2
-->

<!-- markdownlint-disable MD013 MD023 MD033 MD036 MD041 -->
<!-- A centred header needs inline HTML, a banner image, indented headings and
     badge lines past 80 columns, so those five rules are off for this file.
     The prose below still wraps at 80. -->
<div align="center">

  <img src="docs/assets/saeptum-readme-banner.svg" alt="Saeptum — bounded job sandbox library in Rust with Go bindings" height="120" />

  <!-- badge block: groups in the fleet README standard's fixed order -->
  <!-- 2 CI/build -->
  [![CI](https://github.com/plurano/saeptum/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/plurano/saeptum/actions/workflows/ci.yml)
  <!-- 3 security/scorecard -->
  [![OpenSSF Scorecard](https://img.shields.io/badge/OpenSSF-Scorecard-06b6d4?style=for-the-badge&labelColor=111a35)](https://scorecard.dev/viewer/?uri=github.com/plurano/saeptum)
  <!-- 4 standards -->
  [![HISS-21](https://img.shields.io/badge/Standards-HISS--21-06b6d4?style=for-the-badge&logo=nasa&labelColor=111a35)](AGENTS.md)
  [![Power of 10](https://img.shields.io/badge/NASA_JPL-Power_of_10-3b82f6?style=for-the-badge&logo=nasa&labelColor=111a35)](CONTRIBUTING.md#modernized-nasa-jpl-power-of-10-rules)
  [![Conventional Commits](https://img.shields.io/badge/Commits-Conventional-8b5cf6?style=for-the-badge&logo=conventionalcommits&logoColor=white&labelColor=111a35)](CONTRIBUTING.md)
  <!-- 5 licence -->
  [![License](https://img.shields.io/badge/License-EUPL--1.2-3b82f6?style=for-the-badge&labelColor=111a35)](LICENSES/EUPL-1.2.txt)

  **Bounded job sandbox library in Rust with Go bindings**

  *Unified isolation across Firecracker microVMs, WebAssembly capsules, and bubblewrap*

</div>

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

## Standards & Governance

<!-- praetor:readme-governance:start -->
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
<!-- praetor:readme-governance:end -->
