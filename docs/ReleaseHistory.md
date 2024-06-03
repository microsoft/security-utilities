# Release Notes

## Definitions

- RUL => New detection.
- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW => New API or feature.
- PRF => Performance work.
- FPS => False positive reduction in static analysis.
- FNS => Flase negative reduction in static analysis.

# UNRELEASED
- RUL: Add `SEC101/051.LooseSasSecret` detection.
- RUL: Add `SEC101/528.GenericJwt` detection.
- BRK: Rename `WellknownPatterns.HighConfidenceSecurityModels` to `WellknownPatterns.PreciselyClassifiedSecurityKeys`.
- BRK: Rename `WellknownPatterns.LowConfidencePotentialSecurityKeys` to `WellknownPatterns.UnclassifiedPotentialSecurityKeys`.
- BRK: Rename `RegexPattern.GenerateTestExamples` to `RegexPattern.GenerateTruePositiveExamples` (and add matching method for false positive examples).
- BRK: Add `longForm` argument to `IdentifiableSecrets.GenerateCommonAnnotatedKey`, to produce the optional full 64-byte form (which includes the full 4-byte Marvin checksum).
- BRK: Coalesce `AadClientAppIdentifiableCredentialsCurrent` and `AadClientAppIdentifiableCredentialsPrevious` into a single `AadClientAppIdentifiableCredentials` check.
- BRK: Rename `IIdentifiableKey.SniffLiterals` to `IIdentifiableKey.Signatures` to precisely reflect their purpose to signify fixed signatures in keys.
- BUG: Update `IdentifiableScan` to post-process finds (e.g., with checksum validation) to eliminate false positives.
- BUG: Correct `AzureCosmosDBIdentifiableKey` rule id to `SEC101/160` (previously incorrectly listed as `SEC101/163`).
- BUG: Correct length of `SEC101/166.AzureSearchIdentifiableQueryKey` and `SEC101/167.AzureSearchIdentifiableAdminKey` rules to 39 bytes and properly mark it as `DetectionMetadata.Identifiable`.
- BUG: Remove `/AM7` signature + check from rust code.
- NEW: Add `SEC101/190.AzureEventGridIdentifiableKey` check.
- NEW: Create distinct `Detection.CrossCompanyCorrelatingId` property.
- BUG: Harden `IdentifiableSecrets.TryValidateCommonAnnotatedKey` for a variety of invalid inputs.
- BUG: Correct `SEC101/170.AzureMLWebServiceClassicIdentifiableKey` signature to `+AMC`.
- FPS: Correct `SEC101/166.AzureSearchIdentifiableQueryKey` and `SEC101/167.AzureSearchIdentifiableAdminKey` regex to disallow special characters in checksum region.

# 1.4.22 - 05/21/2024
- BUG: Fix `IdentifiableSecrets.ComputeDerivedSymmetricKey` and `IdentifiableSecrets.ComputeDerivedIdentifiableKey` to properly initialize the `HMACSHA256` algorithm with the cask/identifiable secret.

# 1.4.21 - 05/21/2024
- BRK: Rename `IdentifiableSecrets.ComputeDerivedSymmetricKey` to `ComputeDerivedIdentifiableKey`.
- BRK: Update `IdentifiableSecrets.ComputeDerivedIdentifiableKey` to accept an alternate checksum seed for constructing the derived key.
- NEW: Add `CommonAnnotatedSecret` key class for next-generation identifiable secrets.
- NEW: Add `Identifiable.ComputeDerivedCommonAnnotatedKey` to generate keys derived from common annotated secrets.

# 1.4.20 - 05/16/2024
- BRK: Add `ComputeHash32(byte[], ulong, int, int)` helper to bring .NET framework and .NET core APIs into alignment.
- BRK: Return value of `ISecretMaskerDetectSecrets(string)` is `IEnumerable<Detection>` (not `ICollection`) for best yield iterator compatibility.
- BUG: Honor `url-safe` option in key `GenerateCommand` to produce URL-safe base64-encoded patterns.
- NEW: Update `SEC101_158_AzureFunctionIdentifiableKey1` ,`SEC101_176_AzureContainerRegistryIdentifiableKey`, and `SEC101_190_AzureEventGridIdentifiableKey` to derive from `IdentifiableKey` base.
- NEW: Implement preliminary high-performance `IdentifiableScan` engine that consume Rust library for detections.

# 1.4.19 - 05/10/2024
- BRK: Eliminate `Identifiable.TryValidateCommonAnnotatedKey` `checksum` and `customerManagedKey` parameters. Checksums now not configurable for HIS v2.
- BRK: Eliminate `Identifiable.GenerateCommonAnnotated[Test]Key` `checksum` parameter.
- NEW: Add `IIdentifiableKey.EncodeForUrl` property for keys with URL-safe encodings. Also adds `IdentifiableKey` base class for shared 32-bit and 64-bit logic.
- NEW: Update `GenerateTestExamples` for standard keys to produce keys that are obviously test patterns due to character repetition, e.g., `cccccccccccccccccccccccccccccccccTESTCi1lAI=`.
- FNS: Correct length for `SEC101/166.AzureSearchIdentifiableQueryKey` and `SEC101/167.AzureSearchIdentifiableAdminKey`.

# 1.4.18 - 05/10/2024
- NEW: Add `IdentifiableSecrets.ComputeHisV1ChecksumSeed` to derive checksum seeds from versioned string literals, e.g., `ReadKey0`.

# 1.4.17 - 05/05/2024
- PRF: Remove `SHA256` instance creation from `RegexPattern.GenerateCrossCompanyCorrelatingId` to avoid expensive object initialization costs.
- PRF: Add `RegexOption.NonBacktracking` as a default option when available to improve .NET regex engine performance.
- PRF: Add some preliminary benchmarks to solution.

## 1.4.16 - 04/30/2024
- BRK: Update common annotated security key format with new requirements. The format is still not fixed.
- NEW: Make `SecurityMasker.AddPatterns` public.

## 1.4.15 - 04/16/2024
- NEW: Implement `IdentifiableSecrets.ComputeDerivedSymmetricKey` to generate identifiable derived keys from arbitrary identifiable secrets.