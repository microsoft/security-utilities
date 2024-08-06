# Microsoft.Security.Utilities.Core Release History
- NR  => new rule
- PRF => performance work
- FCR => fingerprint change or refactor
- RRR => rule rename or refactor
- FPC => regex candidate reduction
- FNC => regex candidate increase
- FPS => FP reduction in static analysis
- FNS => false negative reduction in static analysis
- FPD => FP reduction in dynamic phase
- FND => False negative reduction in dynamic phase
- UER => eliminate unhandled exceptions in rules
- UEE => eliminate unhandled exceptions in engine
- DEP => upgrade dependency versions
- NEW => new feature 

UNRELEASED
* NEW: Provide `StandardCommonAnnotatedKeySizeInBytes` and `LongFormCommonAnnotatedKeySizeInBytes` constants (63 and 64, respectively).
* NEW: `TryValidateCommonAnnotatedKey(byte[], string)` to facilitate working with keys as byte arrays.
* NEW: `ComputeDerivedCommonAnnotatedKey(string, byte[])` to facilitate working with keys as byte arrays.
* NEW: `GenerateCommonAnnotatedKeyBytes(bool, byte[], byte[], bool, char?)` to facilitate working with keys as byte arrays.
* NEW: Change `ComputeDerivedCommonAnnotatedKey(string, string)` `textToHash` parameter name to `derivationInput` to better reflect its purpose.
* 
## **v1.4.1** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.4.1)
* NEW: Emergent and unfinished classification and redaction capability.

## **v1.4.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.4.0)
* BRK: `CustomAlphabetEncoder.Encode` will default to produce strings at least 6 characters long, but can be overridden by passing a `minLength` parameter.

## **v1.3.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.3.0)
* BRK: Removed `encodeForUrl` parameter from `IdentifiableSecrets.GenerateBase64Key` method, and so this method is restricted to generating keys using the standard base64-encoding alphabet. Added a new method, `GenerateUrlCompatibleBase64Key` method for the URL-friendly case (with an option to include or exclude padding).

## **v1.2.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.2.0)
* BRK: Renamed `IdentifiableSecrets.GenerateIdentifiableKey to IdentifiableSecrets.GenerateBase64Key.

## **v1.1.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.1.0)
* NEW: `CustomAlphabetEncoder` class added to support checksum validations.

## **v1.0.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.0.0)
* NEW: Initial release. Including `Marvin` and `IdentifiableSecrets` classes.