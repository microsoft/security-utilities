# Release Notes

## Definitions

- RUL => New detection.
- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW => New API or feature.
- PRF => Performance work.
- FPS => False positive reduction in static analysis.
- FNS => False negative reduction in static analysis.

# 1.12.0 - 01/06/2025
- BRK: Derived keys and hashed data are no longer supported. The following API are removed:
  - `IdentifiableSecrets.CommonAnnotatedDerivedKeySignature`
  - `IdentifiableSecrets.CommonAnnotatedHashedDataSignature`
  - `IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey`
  - `IdentifiableSecrets.ComputeDerivedIdentifiableKey`
  - `IdentifiableSecrets.ComputeCommonAnnotatedHash`

# 1.11.0 - 01/02/2025
- NEW: Expose `SecretLiteral.Value` as public data.
- FPS: Update `SEC101/127.UrlCredentials` regex to require a word break before the `ftp` or `http` schema rendering.

# 1.10.0 - 01/02/2025
- BRK: Update `SEC101/127.UrlCredentials` match refinement to include both the account name and password. This is a breaking change as the correlating id will differ.
- BUG: Merge multiple calls to `DateTime.UtcNow` in `GenerateCommonAnnotatedKey`, forcing year and month to agree. Add overload to provide an arbitrary allocation time, with bound checks (year 2024 to 2085).
- BUG: Mark `SecretMasker(SecretMasker)` copy contructor as protected to make it callable by derived classes.
- BUG: Mark `SecretMasker.Clone` as public virtual, to make it overridable by derived classes.
- BUG: Update `SEC101/127.UrlCredentials` visibility to public to make it independently creatable.
- BUG: Mark `SecretMasker.LiteralEncoders`, `SecretMasker.EncodedSecretLiterals` and `SecretMasker.ExplicitlyAddedSecretLiterals` as public.
- BUG: Update `SEC101/154.AzureCacheForRedisIdentifiableKey` test example production to call base class (which generates test keys consisting of repeated characters in the randomized component).
- BUG: Short-circuit `SecretMasker.DetectSecret(string)` operation if there are no configured regexes, encoded, or explicitly added secret literals.
- FPS: Update `SEC101/127.UrlCredentials` regex to not fire on use of colon within URL path component.
- FNS: Update `SEC101/127.UrlCredentials` regex to detect ftp(s) credentials.

# 1.9.1 - 11/18/2024
- DEP: Removed dependency of the `base-62` crate in the Rust codebase, since it depended on the `failure` crate which has a known [vulnerability](https://github.com/advisories/GHSA-jq66-xh47-j9f3).
- BUG: Fix unhandled exception raised by `CommonAnnotatedKey.TryCreate(string, out CommonAnnotatedKey)` when passed non-CASK secrets of length < 80.
- BUG: Update `AzureEventGridIdentifiableKey` rule id to `SEC101/199` to be synced with source of the rule.
- BUG: Update `NuGetApiKey` rule id to `SEC101/031` to be synced with source of the rule.

# 1.8.0 - 09/16/2024
- BUG: Mark `SEC000/000.Unclassified32ByteBase64String`, `SEC000/001.Unclassified64ByteBase64String`, `SEC101/101.AadClientAppLegacyCredentials`, `SEC000/001.Unclassified64ByteBase64String` as `DetectionMetadata.LowConfidence`.
- BUG: Mark `SEC101/109.AzureContainerRegistryLegacyKey` as `DetectionMetadata.MediumConfidence`.
- BUG: Mark `SEC101/030.NuGetApiKey`, `SEC101/105.AzureMessageLegacyCredentials`, `SEC101/110.AzureDatabricksPat`,`SEC101/050.NpmAuthorKey`,`SEC101/565.SecretScanningSampleToken` as `DetectionMetadata.HighConfidence`.
- BUG: Make round-tripping of common annotated security keys through base64 encoding/decoding more robust. We previously emitted illegal ending base64 characters (when appending base62 encoded checksums).
- BUG: Correct `IdentifiableSecrets` `ComputeDerivedCommonAnnotatedKey` and `ComputeCommonAnnotatedHash` helpers to preserve all randomized byte input entropy by encoding and decoding this data as base64.
- NEW: Add `CommonAnnotatedKey` `ChecksumBytes` and `ChecksumBytesIndex` convenience methods for retrieving key checksum data.
- PRF: Enable scan pre-filtering by declaring `.servicebus` as `SEC101/105.AzureMessageLegacyCredentials` signature.

# 1.7.0 - 09/10/2024
- BRK: Rename `StandardCommonAnnotatedKeySize` to `StandardEncodedCommonAnnotatedKeySize` and `LongFormCommonAnnotatedKeySize` to `LongFormEncodedCommonAnnotatedKeySize` to distinguish these from const values for key lengths in bytes.
- BUG: Correct `CommonAnnotatedKeyRegexPattern` to detect keys (as denoted by `H` in the platform signature) derived from hashing data with CASK keys or arbitrary secrets.
- BUG: Fix issue in low-level `GenerateCommonAnnotatedTestKey` helper in which key kind signature was hard-coded for `D` (derived) for both derived and hashed keys (which should be denoted by `H`).
- NEW: Add `ComputeCommonAnnotatedHash` to generate annotated fingerprints from arbitrary strings.
- NEW: Add `CommonAnnotatedDerivedKeySignature` and `CommonAnnotatedHashedDataSignature` to denote these generated key variations.
- NEW: Update key generation to use Base62 for all encoded checksums (including primary keys). As a result, all test keys (in which the randomized component is a common character) will be valid (because we no longer will generate special characters in the computed checksum).
- NEW: Add `longForm` argument to `ComputeDerivedCommonAnnotatedKey` and `ComputeCommonAnnotatedHash` to support backwards-compatible, full 64-byte encoded forms of these keys.
- NEW: Provide `ComputeDerivedCommonAnnotatedKey` and `ComputeCommonAnnotatedHash` overloads that accept an arbitrary secret (and which allow platform and provider data to be explicitly specified).

# 1.6.0 - 08/09/2024
- NEW: Provide `StandardCommonAnnotatedKeySizeInBytes` and `LongFormCommonAnnotatedKeySizeInBytes` constants (63 and 64, respectively).
- NEW: `TryValidateCommonAnnotatedKey(byte[], string)` to facilitate working with keys as byte arrays.
- NEW: `ComputeDerivedCommonAnnotatedKey(string, byte[])` to facilitate working with keys as byte arrays.
- NEW: `GenerateCommonAnnotatedKeyBytes(bool, byte[], byte[], bool, char?)` to facilitate working with keys as byte arrays.
- NEW: Change `ComputeDerivedCommonAnnotatedKey(string, string)` `textToHash` parameter name to `derivationInput` to better reflect its purpose.
- NEW: Add preliminary notion of confidence levels.
- BUG: Move `AadClientAppLegacyCredentials34` out of `HighConfidenceMicrosoftSecurityModels` as a noisy check.

# 1.5.2 - 07/05/2024
- NEW: Added an initial secret redaction capability to the Rust package.

# 1.5.1 - 06/27/2024
- DEP: Rust packages now depend on `msvc_spectre_libs` to link Spectre-mitigated libraries for `msvc` targets.
- NEW: Rust packages now support common annotated security key generation and validation, with semantics equivalent to C# version.

# 1.5.0 - 06/18/2024
- RUL: Add `SEC101/061.LooseOAuth2BearerToken` detection.
- DEP: Added support for net451 in `Microsoft.Security.Utilities.Core` for backward compatibility.
- BRK: Remove `SEC101/109.AzureContainerRegistryLegacyKey` as it is too anonymous for standalone secret detection.
- BUG: Resolve `System.ArgumentOutOfRangeException: Index was out of range` and `System.FormatException: The input is not a valid Base-46 string` errors when calling `IdentifiableSecrets.GenerateCommonAnnotatedTestKey(ulong, string, bool, byte[], byte[], bool, char?)`. These exceptions originated in multithreading issues in `Base62.EncodingExtensions.ToBase62(this string)`.
- BUG: Fix the logic in `CommonAnnotatedSecurityKey.GenerateTruePositiveExamples()` to handle invalid test key characters, and to properly break out of the testing loop.
- FNS: Added `SEC101/200.CommonAnnotatedSecurityKey` to `WellKnownPatterns.HighConfidenceMicrosoftSecurityModels`.
- NEW: Add `DetectionMetadata.LowConfidence` and `Detection.MediumConfidence` designations.
- PRF: Eliminate instantiation of `RandomNumberGenerator` object on every key allocation.
- FNS: Add `UrlCredentials` to `WellKnownPatterns.UnclassifiedPotentialSecurityKeys`.
- FNS: Add `Unclassified32CharacterString` to `WellKnownPatterns.UnclassifiedPotentialSecurityKeys`. This rule locates some legacy AAD app passwords as well as legacy Azure container registry keys. 
 
# 1.4.25 - 06/04/2024
- BUG: Bring `IdentifiableScan` into precise equivalence with other maskers, e.g., `Detection.RedactionToken` is now in alignment.
- NEW: Provide hybrid capability to run high-performance detections in `IdentifiableScan` and fall back to other masker as required.

# 1.4.24 - 06/03/2024
- RUL: Add `SEC101/060.LooseSasSecret` detection.
- RUL: Add `SEC101/528.GenericJwt` detection.
- BRK: Rename `WellknownPatterns.HighConfidenceSecurityModels` to `WellknownPatterns.PreciselyClassifiedSecurityKeys`.
- BRK: Rename `WellknownPatterns.LowConfidencePotentialSecurityKeys` to `WellknownPatterns.UnclassifiedPotentialSecurityKeys`.
- BRK: Rename `RegexPattern.GenerateTestExamples` to `RegexPattern.GenerateTruePositiveExamples` (and add matching method for false positive examples).
- BRK: Add `longForm` argument to `IdentifiableSecrets.GenerateCommonAnnotatedKey`, to produce the optional full 64-byte form (which includes the full 4-byte Marvin checksum).
- BRK: Coalesce `AadClientAppIdentifiableCredentialsCurrent` and `AadClientAppIdentifiableCredentialsPrevious` into a single `AadClientAppIdentifiableCredentials` check.
- BRK: Rename `IIdentifiableKey.SniffLiterals` to `IIdentifiableKey.Signatures` to precisely reflect their purpose to signify fixed signatures in keys.
- BUG: Make `microsoft_security_utilities_core` Rust module public. The module cannot be consumed otherwise.
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
