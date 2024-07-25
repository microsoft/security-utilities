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
- DEP: `System.Text.Json` updated to `v8.0.4` to resolve Depandabot alert.
- NEW: Introduces the `ScanEngine` struct, which allows simplified usage in concurrent scenarios---a single `ScanEngine` instance, along with per-thread `ScanState` instances, suffice without the need for additional synchronization. The existing `Scan` struct is operationally unchanged for users.
- BRK: `Send` and `Sync` bounds have been added for `ScanDefinition` validators. This allows `ScanEngine` to be `Send + Sync`.

# 1.5.2 - 07/05/2024
- NEW: Added an initial secret redaction capability to the Rust package.

# 1.5.1 - 06/27/2024
- DEP: Rust packages now depend on `msvc_spectre_libs` to link Spectre-mitigated libraries for `msvc` targets.
- NEW: Rust packages now support common annotated security key generation and validation, with semantics equivalent to C# version.

# 1.4.24 - 06/03/2024
- BUG: Make `microsoft_security_utilities_core` Rust module public. The module cannot be consumed otherwise.
