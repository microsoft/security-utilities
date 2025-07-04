# Release Notes

## Definitions

- RUL => New detection.
- DEP => Update dependency.
- BRK => General breaking change.
- BUG => General bug fix.
- NEW => New API or feature.
- PRF => Performance work.
- RRR => Rule rename, refactor or corrected metadata.
- FPS => False positive reduction in static analysis.
- FNS => False negative reduction in static analysis.

# 1.20.0 - 06/30/2025
- BRK: `SecretLiteral` and `RegexPattern.GetDetections` are no longer public.
- NEW: On .NET 8+, `SecretMasker.DetectSecrets` and `SecretMasker.MaskSecrets` now provide overloads that accept `ReadOnlyMemory<char>` input to allow the caller to avoid string allocation.

# 1.19.0 - 06/05/2025
- BRK, BUG: `SecretMasker.MinimumSecretLengthCeiling` is removed. This property had no effect previously.
- BRK, BUG: `SecretMasker.MinimumSecretLength` is now respected for regex match length in addition to literal value lengths.
- BRK, NEW: A shared `SecretMasker` instance is now fully safe to use from multiple threads. To establish this, it is now sealed and properties that exposed unsynchronized mutable state have been made read-only or removed. The following properties are now read-only: `DefaultRegexRedactionToken`, `DefaultLiteralRedactionToken`. The following properties that returned mutable collections are now removed: `RegexPatterns`, `EncodedSecretLiterals`, `ExplicitlyAddedSecretLiterals`, `LiteralEncoders`.`EncodedSecretLiterals`, `ExplicitlyAddedSecretLiterals`. The limitation that `AddValue` and `AddLiteralEncoder` were only thread safe if there was only one thread adding values is also removed.
- BRK, NEW: For clarity, `SecretMasker.ElapsedTime` now returns a `TimeSpan` instead of a `long` tick count.
- BUG: Fix issue where `SecretMasker.ElapsedTime` could be incorrect when the `SecretMasker` was used concurrently from multiple threads.
- BUG: Lengthening and re-shortening `SecretMasker.MinimumSecretLength` is no longer destructive.
- NEW: `SecretMasker.ElapsedTime` now also counts time spent in `MaskSecrets` exclusive of `DetectSecrets`.
- NEW: `SecretMasker.MaskSecrets` will no longer provide more than one `Detection` with the exact same start index and range to its callback, and will always prioritize literal detections over regex detections.

# 1.18.0 - 05/14/2025
- RUL: Add `SEC101/177.SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey`, `SEC101/197.AzureAppConfigurationLegacyCommonAnnotatedSecurityKey`, `SEC101/198.AzureFluidRelayLegacyCommonAnnotatedSecurityKey`, `SEC101/199.AzureEventGridLegacyCommonAnnotatedSecurityKey`, `SEC101/201.AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat`, `SEC101/202.AzureMixedRealityLegacyCommonAnnotatedSecurityKeyPat`, `SEC101/203.AzureMapsLegacyCommonAnnotatedSecurityKey`, `SEC101/204.AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey`, `SEC101/205.AzureAIServicesLegacyCommonAnnotatedSecurityKey`, `SEC101/206.AzureOpenAILegacyCommonAnnotatedSecurityKey`, `SEC101/207.AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey`, `SEC101/208.AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey`, `SEC101/209.AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey`, `SEC101/210.AzureComputerVisionLegacyCommonAnnotatedSecurityKey`, `SEC101/211.AzureContentModeratorLegacyCommonAnnotatedSecurityKey`, `SEC101/212.AzureContentSafetyLegacyCommonAnnotatedSecurityKey`, `SEC101/213.AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey`, `SEC101/214.AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey`, `SEC101/215.AzureFaceLegacyCommonAnnotatedSecurityKey`, `SEC101/216.AzureFormRecognizerLegacyCommonAnnotatedSecurityKey`, `SEC101/217.AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey`, `SEC101/218.AzureHealthInsightsLegacyCommonAnnotatedSecurityKey`, `SEC101/219.AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey`, `SEC101/220.AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey`, `SEC101/221.AzureKnowledgeLegacyCommonAnnotatedSecurityKey`, `SEC101/222.AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey`, `SEC101/223.AzureLuisLegacyCommonAnnotatedSecurityKey`, `SEC101/224.AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey`, `SEC101/225.AzurePersonalizerLegacyCommonAnnotatedSecurityKey`, `SEC101/226.AzureQnAMakerLegacyCommonAnnotatedSecurityKey`, `SEC101/227.AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey`, `SEC101/228.AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey`, `SEC101/229.AzureSpeechServicesLegacyCommonAnnotatedSecurityKey`, `SEC101/230.AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey`, `SEC101/231.AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey`, `SEC101/232.AzureTextTranslationLegacyCommonAnnotatedSecurityKey`, `SEC101/233.AzureDummyLegacyCommonAnnotatedSecurityKey`, `SEC101/234.AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey`, `SEC101/235.AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey`, `SEC101/236.AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey`, `SEC101/237.AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey`, `SEC101/238.AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey`, `SEC101/239.AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey`, `SEC101/240.AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey`, `SEC101/241.AzureBingSearchLegacyCommonAnnotatedSecurityKey`, `SEC101/242.AzureBingSearchv7LegacyCommonAnnotatedSecurityKey`, `SEC101/243.AzureBingSpeechLegacyCommonAnnotatedSecurityKey`, `SEC101/244.AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey`, and `SEC101/245.AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey` detections.  
- BRK, NEW: `SecretMasker.MaskSecrets` and `ISecretMasker.DetectSecrets` now accept an `Action<Detection>` callback (with a default value of `null`) to receive detections that result from the operation. This is binary-breaking only for `SecretMasker` callers and source-breaking as well for `ISecretMasker` implementations.
- BRK: `Detection` is now sealed and immutable. All property setters and the copy constructor are removed.
- BRK: `Detection`  no longer overrides `Equals` and `GetHashCode` nor implements `IEquatable<Detection>`. `Detection.Equals` and `Detection.GetHashCode` will therefore now be based on reference equality.
- BRK, PRF: `IdentifiableScan` has been removed and its functionality has been merged into `SecretMasker` which now scans the patterns it's given as fast as possible, which will be significantly faster for identifiable key patterns.
- BRK: `SecretMasker.Clone` has been removed.
- BRK: `WellKnownRegexPatterns.*Iterator` methods have been removed. Use the corresponding `WellKnownPatterns.*` properties instead.
- BRK: `WellKnownRegexPatterns.*` properties are now of stronger type`IReadOnlyList<RegexPattern>` instead of `IEnumerable<RegexPattern>`.
- BRK: `SecretMasker.SyncObject` is now a read-only property instead of a public mutable field.
- NEW: `SecretMasker` is now capable of finding identifiable keys without relying on delimiting characters`.
- NEW: Add `RegexPattern.CreatedVersion` and `RegexPattern.LastUpdatedVersion` to track version of rule introduction and last update to rule logic. These versions are emitted to generated rules JSON metadata files.
- PRF: Add high-performance scanning for additional patterns: `SEC101/031.NuGetApiKey`, `SEC101/050.NpmAuthorKey`, `SEC101/110.AzureDatabricksPat`, and `SEC101/565.SecretScanningSampleToken`.
- PRF: Fewer intermediate allocations are performed by `SecretMasker.MaskSecrets`.
- FPS: Prevent `SEC101/105.AzureMessagingLegacyCredentials` from firing on non-legacy keys.

# 1.17.0 - 04/03/2025
- BRK: `RegexPattern.Pattern` is no longer virtual.
- BRK: `RegexPattern.Signatures` is no longer virtual.
- BRK: `IdentifiableKey.ChecksumSeeds` is no longer virtual.
- BRK: `RegexPattern.RotationPeriod` is no longer publicly settable.
- BRK: `IdentifiableKey.RegexNormalizedSignature` is removed.
- BRK: Abstract classes `IdentifiableKey`, `Azure32ByteIdentifiableKey`, `Azure64ByteIdentifiableKey`, and `AzureMessagingIdentifiableKey` now require derived classes to pass their signature to the base constructor.
- BRK: Rename `RegexDefaults.DefaultOptionsCaseSensitive` to `RegexDefaults.DefaultOptions`.
- BRK: Remove `RegexPattern.DefaultRegexOptions`. Use `RegexDefaults.DefaultOptions` instead.
- BRK: `RegexOptions.CultureInvariant` is now used by default.
- BRK: Remove methods on `CachedDotNetRegex` that are not supported by the common `IRegexEngine` interface.
- BRK: Direct use of `CachedDotNetRegex` no longer forces `RegexOptions.Compiled` and `RegexOptions.NonBacktracking`. It is up to the caller to pass them in if overriding the default argument.
- BRK: `RegexOptions` arguments of `RegexPattern` constructor and methods on `IRegexEngine` and `CachedDotNetRegex` are now nullable.
- BRK: If explicit non-null `RegexOptions` are passed to `RegexPattern` constructor, they will be used as-is and will no longer be combined with the default options.
- BRK: Remove derived `RegexPattern` class properties `ChecksumSeeds`, `EncodeForUrl`, and `KeyLength` from generated rules JSON as these are not relevant to the literal authoring of equivalent regex patterns in other languages.
- BRK: Rename `LegacyCommonAnnotatedSecurityKey` to `CommonAnnotatedSecurityKey` and mark this inlined `Microsoft.Security.Utilities` class as internal.
- BUG: `IdentifiableScan` now properly flows `RegexPattern.RotationPeriod` to `Detection` instances. `Detection.RotationPeriod` previously always retained `default` as a value.
- BUG: `IdentifiableScan` now properly flows `RegexPattern.DetectionMetadata` to `Detection` instances. `Detection.DetectionMetadata` was previously hard-coded as `DetectionMetadata.HighEntropy`.
- NEW: Sort properties by name in GeneratedRegexPatterns/*.json.
- NEW: Add `RegexPattern.Label` and `Detection.Label` properties that comprise a readable description of a secret kind, e.g., `an Azure Functions access key`.
- NEW: Add `Detections.Format` helper to return user-facing strings such as `'...444444' is a NuGet API key. The correlating id for this detection is 3wsjgo3hBjSPHdIc2Td1.`.
- NEW: Add `Detections.TruncateSecret` helper to return truncated secrets of specified length.
- NEW: Provide deterministic ordering of properties in GeneratedRegexPatterns/*.json via `DataMember` attributes.
- PRF: Remove unnecessary and expensive recomputation of `RegexPatter.Pattern`, `RegexPattern.Signatures`, and `IdentifiableKey.ChecksumSeeds` on every property access.
- RRR: Rename `CommonAnnotatedSecurityKey` to `UnclassifiedLegacyCommonAnnotatedSecurityKey`.
- RRR: Rename `GenericJwt` to `UnclassifiedJwt`.
- RRR: Rename `AzureMessageLegacyCredentials` to `AzureMessagingLegacyCredentials`.

# 1.16.0 - 03/05/2025
- BRK: Eliminate `SEC000/101.Unclassified32CharacterString` as noisy and not useful.
- BRK: Rename `SEC101/102.AdoPat` friendly name to `AdoLegacyPat`.
- BRK: `IdentifiableScan` no longer supports stream input. The following API are removed. Use `IdentifiableScan.DetectSecrets(string)`.
  -  `IdentifiableScan.DetectSecrets(Stream)`
  -  `IdentifiableScan.Start`
  -  `IdentifiableScan.Scan`
  -  `IdentifiableScan.PossibleMatches`
  -  `IdentifiableScan.GetPossibleMatchRange`
  -  `IdentifiableScan.CheckPossibleMatchRange`
- PRF: `IdentifiableScan` did not use high-performance scanning techniques for `SEC101/178.AzureIotHubIdentifiableKey` and `SEC101/200.CommonAnnotatedSecurityKey`. A bug triggered fallback to slower scanning due to incorrect signatures being used.
- PRF: `IdentifiableScan` now implements high-performance scanning techniques in managed code. The performance has been found to be significantly better than the prior implementation via rust interop. This also reduces the size of the NuGet package size by a factor of 34 from 6.8 MB to 200 KB and adds support for non x86/x64 CPUs and non-Windows OSes.
- BUG: Correct `SEC000/002.Unclassified16ByteHexadecimalString` id and rule name  on calling `GetMatchIdAndName` (where `SEC000/001.Unclassified64ByteBase64String` was returned incorrectly before).
- BUG: Resolve `System.FormatException: The input is not a valid Base-46 string` errors calling `SEC101/102.AdoPat.GetMatchIdAndName` by swallowing correct exception kind `ArgumentException` in `IsChecksumValid` helper.
- BUG: `?P<name>` is now used throughout for named captures as this is required currently for RE2 compatibility.

# 1.15.0 - 03/03/2025
- BRK: Regular expression syntax has been standardized in JSON to conform to how the overwhelming majority of patterns were already defined.
  - `refine` is used now used throughout as the name of the capture group used to isolate an actual find from the full expression that also matches delimiting characters. `secret` was previously used in some instances.
  - `?<name>` is now used throughout for named captures. '?P<name>' was previously used in some instances. This may require replacing '?<' with '?P<' if using a regex engine that only accepts the '?P<name>' syntax.
  - Impacted rules:
      - `SEC101/104.AzureCosmosDBLegacyCredentials`
      - `SEC101/105.AzureMessagingLegacyCredentials`
      - `SEC101/110.AzureDatabricksPat`
      - `SEC101/200.CommonAnnotatedSecurityKey`
      - `SEC101/565.SecretScanningSampleToken`
- BRK: `CachedDotNetRegexEngine`will no longer accept `(?P<name>)` syntax. This is only relevant if it is used with patterns other than those distributed with this library.
- BRK: `IdentifiableSecrets.ComputeDerivedCommonAnnotatedKey` now exclusively throws `System.ArgumentException` for invalid key inputs (no longer raising `System.FormatException: The input is not a valid Base-46 string` for invalid data).
- BUG: `SEC101/200.CommonAnnotatedSecurityKey` and `SEC101/565.SecretScanningSampleToken` considered non-alphanumeric delimiter preceding secret to be part of the match.
- BUG  `SEC101/061.LooseOAuth2BearerToken` had incorrect signatures, causing no matches to be found unless the input happened to also contain `sig=` or `ret=`.
- BUG: Resolve `System.FormatException: The input is not a valid Base-46 string` errors calling `IdentifiableSecrets.ValidateChecksum` with invalid base64. The API now returns `false` in this case.
- BUG: Resolve 'System.NullReferenceException` on calling `RegexPattern.GetMatchMoniker` when its internal call to `GetMatchIdAndName` return null. A null return from `GetMatchIdAndName` is an expected value that indicates post-processing has determined there is no actual match.
- BUG: Resolve `System.FormatException: The input is not a valid Base-46 string` errors calling `SEC101/102.AdoPat.GetMatchIdAndName` with invalid base64. The API now returns null in this case (the standard behavior when post-processing does not detect a match).
 
# 1.14.0 - 02/25/2025
- RUL: Add `DAT101/001.GuidValue` detection as part of a new DAT101 detection series which helps classify non-sensitive data.
- RUL: Add `DAT101/002.IPv4` non-sensitive data classification.
- RUL: Add `DAT101/003.IPv6` non-sensitive data classification.
- RUL: Add `DAT101/004.Integer` non-sensitive data classification.
- RUL: Add `DAT101/005.Float` non-sensitive data classification.
- RUL: Add `SEC101/055.Pkcs12CertificatePrivateKeyBundle` detection. This is currently solely regex based and does not yet guarantee fully-formed PKCS #12.
- BRK: .NET 6.0 and 7.0 are no longer supported as they have reached end-of-life. Use a [supported version version of .NET](https://dotnet.microsoft.com/en-us/platform/support/policy/dotnet-core).
- BRK: .NET Framework 4.5.1 through 4.6.0 are no longer supported. Use a version of .NET Framework version that supports [.NET Standard 2.0](https://learn.microsoft.com/en-us/dotnet/standard/net-standard?tabs=net-standard-2-0): NET 4.6.1 or greater with .NET 4.7.2 or greater strongly recommended. Note that there are no supported versions of Windows that have a version of .NET Framework that would be affected by this change at runtime, but build changes may be required.

# 1.13.0 - 02/05/2025
- FNS: Eliminate false negatives resulting from incorrectly specifying `=` as a delimiting character in the core 'identifiable' rules. This broke simple patterns such as `myKey=an_actual_key`.
- FNS: Eliminate false negatives resulting from improper use of the `-` character in regexes (where it was interpreted as a range operator not a literal).,
- BUG: `IdentifiableSecrets.TryValidateCommonAnnotatedKey(byte[], string)` did not validate signature argument to be be exactly 4 characters long, beginning with a letter, entirely alphanumeric, and either entirely uppercase or entirely lowercase. 
- BUG: `IdentifiableSecrets.TryValidateCommonAnnotatedKey` (all overloads)  did not check that the key had the given signature and would return true for any valid key.
- BUG: `IdentifiableSecrets.(Try)ValidateBase64Key`, when given a backwards-compatible `CommonAnnotatedKey`, did not check that the key had the given signature.
- BUG: `IdentifiableSecrets.(Try)ValidateBase64Key` failed on .NET 8 with `System.NotSupportedException: The specified pattern with RegexOptions.NonBacktracking could result in an automata as large as 'NNNN' nodes, which is larger than the configured limit of '1000'.` This was due to using a regex with a quantifier that was too large, and fixed by removing the regex entirely.
- PRF: `IdentifiableSecrets.(Try)ValidateBase64Key` is much faster now as it no longer generates nor uses regular expressions.

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
- BUG: Correct `AzureEventGridIdentifiableKey` rule id from `SEC101/190` to `SEC101/199` to be synced with source of the rule.
- BUG: Update `NuGetApiKey` rule id to `SEC101/031` to be synced with source of the rule.

# 1.8.0 - 09/16/2024
- BUG: Mark `SEC000/000.Unclassified32ByteBase64String`, `SEC000/001.Unclassified64ByteBase64String`, `SEC101/101.AadClientAppLegacyCredentials`, `SEC000/001.Unclassified64ByteBase64String` as `DetectionMetadata.LowConfidence`.
- BUG: Mark `SEC101/109.AzureContainerRegistryLegacyKey` as `DetectionMetadata.MediumConfidence`.
- BUG: Mark `SEC101/030.NuGetApiKey`, `SEC101/105.AzureMessageLegacyCredentials`, `SEC101/110.AzureDatabricksPat`, `SEC101/050.NpmAuthorKey`, `SEC101/565.SecretScanningSampleToken` as `DetectionMetadata.HighConfidence`.
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
- BUG: Resolve `System.ArgumentOutOfRangeException: Index was out of range` and `System.FormatException: The input is not a valid Base-46 string` errors calling `IdentifiableSecrets.GenerateCommonAnnotatedTestKey(ulong, string, bool, byte[], byte[], bool, char?)`. These exceptions originated in multithreading issues in `Base62.EncodingExtensions.ToBase62(this string)`.
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
- RUL: Add `SEC101/199.AzureEventGridIdentifiableKey` detection.
- BRK: Add `ComputeHash32(byte[], ulong, int, int)` helper to bring .NET framework and .NET core APIs into alignment.
- BRK: Return value of `ISecretMaskerDetectSecrets(string)` is `IEnumerable<Detection>` (not `ICollection`) for best yield iterator compatibility.
- BUG: Honor `url-safe` option in key `GenerateCommand` to produce URL-safe base64-encoded patterns.
- NEW: Update `SEC101/158.AzureFunctionIdentifiableKey` and `SEC101/176.AzureContainerRegistryIdentifiableKey` to derive from `IdentifiableKey` base.
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

## 1.4.14 - 04/16/2024
## 1.4.13 - 04/09/2024

## 1.4.12 - 04/09/2024
- RUL: Add `SEC000/000.Unclassified32ByteBase64String` detection.
- RUL: Add `SEC000/001.Unclassified64ByteBase64String` detection.
- RUL: Add `SEC000/002.Unclassified16ByteHexadecimalString` detection.
- RUL: Add `SEC101/105.AzureMessagingLegactyCredentials` detection.
- RUL: Add `SEC101/110.AzureDatabricksPat` detection.

## 1.4.11 - 04/08/2024
- RUL: Add `SEC101/101.AadClientAppLegacyCredentials` detection.
- RUL: Add `SEC101/565.SecretScanningSampleToken` detection.

## 1.4.10 - 04/08/2024
- RUL: Add `SEC101/102.AdoPat` detection.
- RUL: Add `SEC101/104.AzureCosmosDBLegacyCredentials` detection.
- RUL: Add `SEC101/106.AzureStorageAccountLegacyCredentials` detection.
- RUL: Add `SEC101/154.AzireCacheForRedisIdentifiableKey` detection.
- RUL: Add `SEC101/171.AzureServiceBusIdentifiableKey` detection.
- RUL: Add `SEC101/172.AzureEventHubIdentifiableKey` detection.
- RUL: Add `SEC101/173.AzureRelayIdentifiableKey` detection.

## 1.4.9 - 04/03/2024
## 1.4.8 - 04/02/2024
## 1.4.7 - 04/02/2024
## 1.4.6 - 03/20/2024
## 1.4.5 - 03/19/2024
## 1.4.4 - 03/18/2024
## 1.4.3 - 03/13/2024

## 1.4.2 - 03/13/2024
- RUL: Add `SEC101/127.UrlCredentials` detection.
- RUL: Add `SEC101/031.NuGetApiKey` detection.
- RUL: Add `SEC101/152.AzureStorageAccountIdentifiableKey` detection.
- RUL: Add `SEC101/156.AadClientAppSecret` detection.
- RUL: Add `SEC101/158.AzureFunctionIdentifiableKey` detection.
- RUL: Add `SEC101/160.AzureCosmosDbIdentifiableKey` detection.
- RUL: Add `SEC101/163.AzureBatchIdentifiableKey` detection.
- RUL: Add `SEC101/166.AzureSearchIdentifiableQueryKey` detection.
- RUL: Add `SEC101/170.AzureMLWebServiceClassicIdentifiableKey` detection.
- RUL: Add `SEC101/171.AzureServiceBusIdentifiableKey` detection.
- RUL: Add `SEC101/172.AzureEventHubIdentifiableKey` detection.
- RUL: Add `SEC101/173.AzureRelayIdentifiableKey` detection.
- RUL: Add `SEC101/176.AzureContainerRegistryIdentifiableKey` detection.
- RUL: Add `SEC101/178.AzureIotHubIdentifiableKey` detection.
- RUL: Add `SEC101/179.AzureIotDeviceProvisioningIdentifiableKey` detection.
- RUL: Add `SEC101/180.AzureIotDeviceIdentifiableKey` detection.
- RUL: Add `SEC101/181.AzureApimIdentifiableDirectManagementKey` detection.
- RUL: Add `SEC101/182.AzureApimIdentifiableSubscriptionKey` detection.
- RUL: Add `SEC101/183.AzureApimIdentifiableGatewayKey` detection.
- RUL: Add `SEC101/184.AzureApimIdentifiableRepositoryKey` detection.