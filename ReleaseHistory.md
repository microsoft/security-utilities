# Microsoft.Security.Utilities Release History

## **v1.4.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.4.0)
* BREAKING: `CustomAlphabetEncoder.Encode` will default to produce strings at least 6 characters long, but can be overridden by passing a `minLength` parameter.

## **v1.3.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.3.0)
* BREAKING: Removed `encodeForUrl` parameter from `IdentifiableSecrets.GenerateBase64Key` method, and so this method is restricted to generating keys using the standard base64-encoding alphabet. Added a new method, `GenerateUrlCompatibleBase64Key` method for the URL-friendly case (with an option to include or exclude padding).

## **v1.2.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.2.0)
* BREAKING: Renamed `IdentifiableSecrets.GenerateIdentifiableKey to IdentifiableSecrets.GenerateBase64Key.

## **v1.1.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.1.0)
* FEATURE: `CustomAlphabetEncoder` class added to support checksum validations.

## **v1.0.0** [NuGet Package](https://www.nuget.org/packages/Microsoft.Security.Utilities/1.0.0)
* FEATURE: Initial release. Including `Marvin` and `IdentifiableSecrets` classes.