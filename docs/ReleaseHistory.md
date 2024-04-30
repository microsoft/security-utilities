# Release Notes

## Definitions

- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW -> New API or feature.
- PRF => Performance work.

## 1.4.16 - 04/30/2024
- BRK: Update common annotated security key format with new requirements. The format is still not fixed.
- NEW: Make `SecurityMasker.AddPatterns` public.

## 1.4.15 - 04/16/2024
- NEW: Implement `IdentifiableSecrets.ComputeDerivedSymmetricKey` to generate identifiable derived keys from arbitrary identifiable secrets.
- 