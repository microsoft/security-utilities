# Release Notes
This document contains release notes pertaining to the Rust crates.

## Definitions

- RUL => New detection.
- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW => New API or feature.
- PRF => Performance work.
- FPS => False positive reduction in static analysis.
- FNS => False negative reduction in static analysis.

# UNRELEASED
- FNS: Add detection of derived and hashed HIS v2 keys for `SEC101/200: Microsoft common annotated security key (HIS v2)`.

# 1.5.4 - 11/19/2024
- DEP: Removed dependency of the `base-62` crate since it depended on the `failure` crate which has a known [vulnerability](https://github.com/advisories/GHSA-jq66-xh47-j9f3).
- NEW: Introduce `marvin::{compute_hash_slice, compute_hash32_slice}` to compute marvin checksums directly from slices. `marvin::{compute_hash, compute_hash32}` also rely on the new, faster implementation.

# 1.5.3 - 07/26/2024
- DEP: `System.Text.Json` updated to `v8.0.4` to resolve Dependabot alert.
- NEW: Introduces the `ScanEngine` struct, which allows simplified usage in concurrent scenarios---a single `ScanEngine` instance, along with per-thread `ScanState` instances, suffice without the need for additional synchronization. The existing `Scan` struct is operationally unchanged for users.
- BRK: `Send` and `Sync` bounds have been added for `ScanDefinition` validators. This allows `ScanEngine` to be `Send + Sync`.

# 1.5.2 - 07/05/2024
- NEW: Added an initial secret redaction capability to the Rust package.

# 1.5.1 - 06/27/2024
- DEP: Rust packages now depend on `msvc_spectre_libs` to link Spectre-mitigated libraries for `msvc` targets.
- NEW: Rust packages now support common annotated security key generation and validation, with semantics equivalent to C# version.

# 1.4.24 - 06/03/2024
- BUG: Make `microsoft_security_utilities_core` Rust module public. The module cannot be consumed otherwise.
