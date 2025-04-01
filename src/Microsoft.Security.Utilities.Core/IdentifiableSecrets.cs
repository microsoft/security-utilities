// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Base62;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A static class that contains constants and utilities for working with identifiable secrets.
/// </summary>
public static class IdentifiableSecrets
{
    [ThreadStatic]
    private static RandomNumberGenerator s_generator;

    public static readonly ulong VersionTwoChecksumSeed = ComputeHisV1ChecksumSeed("Default0");

    public const string CommonAnnotatedKeyRegexPattern = "[A-Za-z0-9]{52}JQQJ9(9|D|H)[A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}([A-Za-z0-9]{2}==)?";

    public static readonly Regex CommonAnnotatedKeyRegex = new(CommonAnnotatedKeyRegexPattern, RegexDefaults.DefaultOptionsCaseSensitive);

    public static uint MaximumGeneratedKeySize => 4096;

    public static uint MinimumGeneratedKeySize => 24;

    public static uint StandardCommonAnnotatedKeySizeInBytes => 63;

    public static uint LongFormCommonAnnotatedKeySizeInBytes => 64;

    public static uint StandardEncodedCommonAnnotatedKeySize => 84;

    public static uint LongFormEncodedCommonAnnotatedKeySize => 88;

    public static string CommonAnnotatedKeyCoreSignature = "JQQJ";

    public static string CommonAnnotatedKeySignature => $"{CommonAnnotatedKeyCoreSignature}99";

    internal static string CommonAnnotatedDerivedKeySignature => $"{CommonAnnotatedKeyCoreSignature}9D";

    internal static string CommonAnnotatedHashedDataSignature => $"{CommonAnnotatedKeyCoreSignature}9H";

    public static bool IsBase62EncodingChar(this char ch)
    {
        return (ch >= 'a' && ch <= 'z') ||
               (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9');
    }

    public static bool IsBase64EncodingChar(this char ch)
    {
        return ch.IsBase62EncodingChar() ||
               ch == '+' ||
               ch == '/';
    }

    public static bool IsBase64UrlEncodingChar(this char ch)
    {
        return ch.IsBase62EncodingChar() ||
               ch == '-' ||
               ch == '_';
    }

    public static bool TryValidateCommonAnnotatedKey(byte[] key,
                                                     string base64EncodedSignature)
    {
        if (key == null ||
            (key.Length != StandardCommonAnnotatedKeySizeInBytes && key.Length != LongFormCommonAnnotatedKeySizeInBytes))
        {
            return false;
        }

        try
        {
            ValidateCommonAnnotatedKeySignature(base64EncodedSignature);
        }
        catch (ArgumentException)
        {
            return false;
        }

        string signature = GetBase64EncodedSignature(key);
        if (!string.Equals(signature, base64EncodedSignature, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool longForm = key.Length == LongFormCommonAnnotatedKeySizeInBytes;

        ulong checksumSeed = VersionTwoChecksumSeed;

        int firstChecksumByteIndex = CommonAnnotatedKey.ChecksumBytesIndex;
        byte[] bytesToChecksum = new byte[firstChecksumByteIndex];
        Array.Copy(key, bytesToChecksum, bytesToChecksum.Length);

        int checksum = Marvin.ComputeHash32(bytesToChecksum, checksumSeed, 0, bytesToChecksum.Length);
        byte[] computedChecksumBytes = BitConverter.GetBytes(checksum);

        int checksumLength = longForm ? 4 : 3;
        byte[] encodedChecksumBytes = new byte[checksumLength];
        Array.Copy(key, firstChecksumByteIndex, encodedChecksumBytes, 0, checksumLength);

        if (encodedChecksumBytes[0] == computedChecksumBytes[0] &&
            encodedChecksumBytes[1] == computedChecksumBytes[1] &&
            encodedChecksumBytes[2] == computedChecksumBytes[2])
        {
            return !longForm || encodedChecksumBytes[3] == computedChecksumBytes[3];
        }

        byte[] base62EncodedBytes = GetBase62ChecksumBytes(computedChecksumBytes);

        if (encodedChecksumBytes[0] != base62EncodedBytes[0] ||
            encodedChecksumBytes[1] != base62EncodedBytes[1] ||
            encodedChecksumBytes[2] != base62EncodedBytes[2])
        {
            return false;
        }

        return !longForm || encodedChecksumBytes[3] == base62EncodedBytes[3];
    }

    private static string GetBase64EncodedSignature(byte[] key)
    {
        Debug.Assert(CommonAnnotatedKey.ProviderFixedSignatureOffset % 4 == 0);
        Debug.Assert(CommonAnnotatedKey.ProviderFixedSignatureLength % 4 == 0);
        const int signatureByteOffset = CommonAnnotatedKey.ProviderFixedSignatureOffset / 4 * 3;
        const int signatureByteLength = CommonAnnotatedKey.ProviderFixedSignatureLength / 4 * 3;
        return Convert.ToBase64String(key, signatureByteOffset, signatureByteLength);
    }

    public static bool TryValidateCommonAnnotatedKey(string key,
                                                     string base64EncodedSignature)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            return false;
        }

        if (key.Length != StandardEncodedCommonAnnotatedKeySize && key.Length != LongFormEncodedCommonAnnotatedKeySize)
        {
            return false;
        }

        try
        {
            ValidateCommonAnnotatedKeySignature(base64EncodedSignature);
        }
        catch (ArgumentException)
        {
            return false;
        }

        string signature = key.Substring(CommonAnnotatedKey.ProviderFixedSignatureOffset, CommonAnnotatedKey.ProviderFixedSignatureLength);
        if (!string.Equals(signature, base64EncodedSignature, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        bool longForm = key.Length == LongFormEncodedCommonAnnotatedKeySize;

        ulong checksumSeed = VersionTwoChecksumSeed;

        string componentToChecksum = key.Substring(0, CommonAnnotatedKey.ChecksumOffset);
        string checksumText = key.Substring(CommonAnnotatedKey.ChecksumOffset);

        byte[] keyBytes = Convert.FromBase64String(componentToChecksum);

        int checksum = Marvin.ComputeHash32(keyBytes, checksumSeed, 0, keyBytes.Length);

        byte[] checksumBytes = BitConverter.GetBytes(checksum);

        string encodedFullChecksum = GetBase62EncodedChecksum(checksumBytes);

        if (encodedFullChecksum.StartsWith(checksumText.Trim('=')))
        {
            return true;
        }

        // A long-form has a full 4-byte checksum, while a standard form has only 3.
        encodedFullChecksum = Convert.ToBase64String(checksumBytes, 0, longForm ? 4 : 3);
        return encodedFullChecksum == checksumText;
    }

    /// <summary>
    /// Generate a <see cref="ulong"/> an HIS v1 compliant checksum seed from a string literal
    /// that is 8 characters long and ends with at least one digit, e.g., 'ReadKey0', 'RWSeed00',
    /// etc. The checksum seed is used to initialize the Marvin32 algorithm to watermark a
    /// specific class of generated security keys.
    /// </summary>
    /// <param name="versionedKeyKind">A readable name that identifies a specific set of generated keys with at least one trailing digit in the name.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static ulong ComputeHisV1ChecksumSeed(string versionedKeyKind)
    {
        if (versionedKeyKind == null)
        {
            throw new ArgumentNullException(nameof(versionedKeyKind));
        }

        if (versionedKeyKind.Length != 8 ||
            !char.IsDigit(versionedKeyKind[7]))
        {
            throw new ArgumentException("The versioned literal must be 8 characters long and end with a digit.");
        }

        // We obtain the bytes of the string literal, reverse them and then convert them to a ulong.
        // Because the string literal has a trailing number, if this number is incremented, the next
        // version of the seed will be very close in number to previous versions. All of this work
        // attempting to ensure the versionability of seeds is future-proofing of uncertain value.
        ulong result = BitConverter.ToUInt64(Encoding.ASCII.GetBytes(versionedKeyKind).Reverse().ToArray(), 0);
        return result;
    }

    internal static byte[] ComputeDerivedCommonAnnotatedKey(string derivationInput,
                                                          byte[] commonAnnotatedSecret,
                                                          bool longForm = false)
    {
        string keyText = Convert.ToBase64String(commonAnnotatedSecret);
        string derivedKey = ComputeDerivedCommonAnnotatedKey(derivationInput, keyText, longForm);
        return Convert.FromBase64String(derivedKey);
    }

    internal static string ComputeDerivedCommonAnnotatedKey(string derivationInput,
                                                          string commonAnnotatedSecret,
                                                          bool longForm = false)
    {
        return ComputeCommonAnnotatedHash(derivationInput, commonAnnotatedSecret, longForm, 'D');
    }

    internal static byte[] ComputeCommonAnnotatedHash(string textToHash,
                                                    byte[] commonAnnotatedSecret,
                                                    bool longForm = false)
    {
        string keyText = Convert.ToBase64String(commonAnnotatedSecret);
        string hash = ComputeCommonAnnotatedHash(textToHash, keyText, longForm, 'H');
        return Convert.FromBase64String(hash);
    }

    internal static string ComputeCommonAnnotatedHash(string textToHash,
                                                    string commonAnnotatedSecret,
                                                    bool longForm = false,
                                                    char hashedDataSignature = 'H')
    {
        if (hashedDataSignature != 'D' && hashedDataSignature != 'H')
        {
            throw new ArgumentException("The hashed data signature must be either 'D' (for derived keys) or 'H' (for arbitrary hashes).");
        }

        if (!CommonAnnotatedKey.TryCreate(commonAnnotatedSecret, out CommonAnnotatedKey cask))
        {
            throw new ArgumentException("The provided key is not a valid common annotated security key.");
        }

        return ComputeCommonAnnotatedHash(textToHash,
                                          cask.Bytes,
                                          cask.ProviderFixedSignature,
                                          cask.IsCustomerManaged,
                                          Convert.FromBase64String(cask.PlatformReserved),
                                          Convert.FromBase64String(cask.ProviderReserved),
                                          longForm,
                                          hashedDataSignature);
    }

    public static byte[] GenerateCommonAnnotatedKeyBytes(string base64EncodedSignature,
                                                         bool customerManagedKey,
                                                         byte[] platformReserved,
                                                         byte[] providerReserved,
                                                         bool longForm = false,
                                                         char? testChar = null)
    {
        string key = GenerateCommonAnnotatedKey(base64EncodedSignature,
                                                customerManagedKey,
                                                platformReserved,
                                                providerReserved,
                                                longForm,
                                                testChar);

        return Convert.FromBase64String(key);
    }

    internal static string ComputeCommonAnnotatedHash(string textToHash,
                                                    byte[] secret,
                                                    string base64EncodedSignature,
                                                    bool customerManagedKey,
                                                    byte[] platformReserved,
                                                    byte[] providerReserved,
                                                    bool longForm = false,
                                                    char keyKindSignature = 'H')
    {
        if (keyKindSignature != 'D' && keyKindSignature != 'H')
        {
            throw new ArgumentException("The hashed data signature must be either 'D' (for derived keys) or 'H' (for arbitrary hashes).");
        }

        using var hmac = new HMACSHA512(secret);
        byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(textToHash));

        byte[] derivedKeyBytes = new byte[40];
        Array.Copy(hashBytes, derivedKeyBytes, derivedKeyBytes.Length);

        return GenerateCommonAnnotatedTestKey(derivedKeyBytes,
                                              VersionTwoChecksumSeed,
                                              base64EncodedSignature,
                                              customerManagedKey,
                                              platformReserved,
                                              providerReserved,
                                              longForm,
                                              testChar: null,
                                              keyKindSignature);
    }

    public static string GenerateCommonAnnotatedKey(string base64EncodedSignature,
                                                    bool customerManagedKey,
                                                    byte[] platformReserved,
                                                    byte[] providerReserved,
                                                    bool longForm = false,
                                                    char? testChar = null)
    {
        return GenerateCommonAnnotatedTestKey(randomBytes: null,
                                              VersionTwoChecksumSeed,
                                              base64EncodedSignature,
                                              customerManagedKey,
                                              platformReserved,
                                              providerReserved,
                                              longForm,
                                              testChar,
                                              keyKindSignature: '9');
    }

    public static string GenerateCommonAnnotatedTestKey(byte[] randomBytes,
                                                        ulong checksumSeed,
                                                        string base64EncodedSignature,
                                                        bool customerManagedKey,
                                                        byte[] platformReserved,
                                                        byte[] providerReserved,
                                                        bool longForm,
                                                        char? testChar,
                                                        char keyKindSignature)
    {
        return GenerateCommonAnnotatedTestKey(randomBytes,
                                              checksumSeed,
                                              base64EncodedSignature,
                                              customerManagedKey,
                                              platformReserved,
                                              providerReserved,
                                              longForm,
                                              testChar,
                                              keyKindSignature,
                                              DateTime.UtcNow);
    }

    public static string GenerateCommonAnnotatedTestKey(byte[] randomBytes,
                                                        ulong checksumSeed,
                                                        string base64EncodedSignature,
                                                        bool customerManagedKey,
                                                        byte[] platformReserved,
                                                        byte[] providerReserved,
                                                        bool longForm,
                                                        char? testChar,
                                                        char keyKindSignature,
                                                        DateTime allocationTime)
    {
        const int platformReservedLength = 9;
        const int providerReservedLength = 3;

        ValidateCommonAnnotatedKeySignature(base64EncodedSignature);

        if (platformReserved != null && platformReserved?.Length != platformReservedLength)
        {
            throw new ArgumentOutOfRangeException(nameof(platformReserved),
                                                  $"When provided, there must be {platformReservedLength} reserved bytes for platform metadata.");
        }

        if (providerReserved != null && providerReserved?.Length != providerReservedLength)
        {
            throw new ArgumentOutOfRangeException(nameof(providerReserved),
                                                  $"When provided, there must be {providerReservedLength} reserved bytes for resource provider metadata.");
        }

        if (platformReserved == null)
        {
            platformReserved = new byte[platformReservedLength];
        }

        if (providerReserved == null)
        {
            providerReserved = new byte[providerReservedLength];
        }

        if (allocationTime.Kind != DateTimeKind.Utc)
        {
            throw new ArgumentException(nameof(allocationTime), "The allocation time must be in UTC.");
        }

        // 2085 is 61 years after 2024. A base62 character is used to express the year (A = 2024 up to 9 = 2085).
        // An allocation time before 2024 or after 2085 is outside of the possible range a base62 character can express.
        if (allocationTime.Year < 2024 || allocationTime.Year > 2085)
        {
            throw new ArgumentOutOfRangeException(nameof(allocationTime), "The allocation year must be between 2024 and 2085, inclusive.");
        }

        base64EncodedSignature = customerManagedKey
                ? base64EncodedSignature.ToUpperInvariant()
                : base64EncodedSignature.ToLowerInvariant();

        string key = null;

        int keyLengthInBytes = 66;
        byte[] keyBytes = new byte[keyLengthInBytes];

        if (testChar == null)
        {
            if (randomBytes == null)
            {
                s_generator ??= RandomNumberGenerator.Create();
                s_generator.GetBytes(keyBytes);
            }
            else
            {
                Array.Copy(randomBytes, keyBytes, randomBytes.Length);
            }

            key = keyBytes.ToBase62();
            key = key.Substring(0, 85);

            // We use Q== as the suffix to keep the key format consistent with the usage in Rust.
            // In C#, the base64 decoder can handle illegal base64 strings, but not in Rust.
            key = $"{key}Q==";
        }
        else
        {
            // We use Q== as the suffix to keep the key format consistent with the usage in Rust.
            // In C#, the base64 decoder can handle illegal base64 strings, but not in Rust.
            key = $"{new string(testChar!.Value, 85)}Q==";
        }

        keyBytes = Convert.FromBase64String(key);
        byte jBits = 'J' - 'A';
        byte qBits = 'Q' - 'A';

        int reserved = (jBits << 18) | (qBits << 12) | (qBits << 6) | jBits;
        byte[] reservedBytes = BitConverter.GetBytes(reserved);

        keyBytes[keyBytes.Length - 25] = reservedBytes[2];
        keyBytes[keyBytes.Length - 24] = reservedBytes[1];
        keyBytes[keyBytes.Length - 23] = reservedBytes[0];

        // Simplistic timestamp computation.
        byte yearsSince2024 = (byte)(allocationTime.Year - 2024);
        byte zeroIndexedMonth = (byte)(allocationTime.Month - 1);

        byte orgBits = 61; // Base64 encoding for '9'
        byte keyKindBits = (byte)(keyKindSignature == '9' ? 61 : keyKindSignature - 'A');

        int? metadata = (orgBits << 18) | (keyKindBits << 12) | (yearsSince2024 << 6) | zeroIndexedMonth;
        byte[] metadataBytes = BitConverter.GetBytes(metadata.Value);

        keyBytes[keyBytes.Length - 22] = metadataBytes[2];
        keyBytes[keyBytes.Length - 21] = metadataBytes[1];
        keyBytes[keyBytes.Length - 20] = metadataBytes[0];

        keyBytes[keyBytes.Length - 19] = platformReserved[0];
        keyBytes[keyBytes.Length - 18] = platformReserved[1];
        keyBytes[keyBytes.Length - 17] = platformReserved[2];
        keyBytes[keyBytes.Length - 16] = platformReserved[3];
        keyBytes[keyBytes.Length - 15] = platformReserved[4];
        keyBytes[keyBytes.Length - 14] = platformReserved[5];
        keyBytes[keyBytes.Length - 13] = platformReserved[6];
        keyBytes[keyBytes.Length - 12] = platformReserved[7];
        keyBytes[keyBytes.Length - 11] = platformReserved[8];

        keyBytes[keyBytes.Length - 10] = providerReserved[0];
        keyBytes[keyBytes.Length - 9] = providerReserved[1];
        keyBytes[keyBytes.Length - 8] = providerReserved[2];

        int signatureOffset = keyBytes.Length - 7;
        byte[] sigBytes = Convert.FromBase64String(base64EncodedSignature);
        sigBytes.CopyTo(keyBytes, signatureOffset);

        int checksum = Marvin.ComputeHash32(keyBytes, checksumSeed, 0, keyBytes.Length - 4);

        byte[] checksumBytes = BitConverter.GetBytes(checksum);
        string checksumText = GetBase62EncodedChecksum(checksumBytes);

        key = $"{Convert.ToBase64String(keyBytes).Substring(0, 80)}{checksumText}";

#if DEBUG
        string roundTripped = Convert.ToBase64String(Convert.FromBase64String(key));
        if (!roundTripped.Equals(key))
        {
            throw new InvalidOperationException("Round-tripped key did not match.");
        }
#endif

        if (!longForm)
        {
            key = key.Substring(0, key.Length - 4);
        }

        return key;
    }

    internal static string GetBase62EncodedChecksum(byte[] checksumBytes)
    {
        checksumBytes = GetBase62ChecksumBytes(checksumBytes);
        return Convert.ToBase64String(checksumBytes);
    }

    internal static byte[] GetBase62ChecksumBytes(byte[] checksumBytes)
    {
        string checksumText = checksumBytes.ToBase62();
        checksumText = $"{checksumText}{new string('0', 6 - checksumText.Length)}==";

        return Convert.FromBase64String(checksumText);
    }

    internal static string ComputeDerivedIdentifiableKey(string textToHash,
                                                       string identifiableHashSecret,
                                                       ulong primaryChecksumSeed,
                                                       ulong? derivedChecksumSeed = null,
                                                       bool encodeForUrl = false)
    {
        string signature = identifiableHashSecret.Trim('=');
        signature = signature.Substring(signature.Length - 10, 4);

        derivedChecksumSeed ??= primaryChecksumSeed;

        if (!TryValidateBase64Key(identifiableHashSecret, primaryChecksumSeed, signature, encodeForUrl))
        {
            throw new ArgumentException("The provided key is not a valid identifiable secret.");
        }

        using var hmac = new HMACSHA256(Encoding.UTF8.GetBytes(identifiableHashSecret));

        byte[] textToHashBytes = Encoding.UTF8.GetBytes(textToHash);
        byte[] hashBytes = hmac.ComputeHash(textToHashBytes);

        byte[] derivedKeyBytes = new byte[42];
        Array.Copy(hashBytes, derivedKeyBytes, hashBytes.Length);

        // This magic introduces a signature of 'deri' that precedes
        // the standard provider fixed signature. This is evidence of
        // a derived key (which is distinct from examining the fixed
        // length of the key). This operation allow us to clearly
        // distinguish a derived key from a standard key that otherwise
        // meets the same length constraints this API happens to produce.
        derivedKeyBytes[31] = (byte)((derivedKeyBytes[31] & 0xC0) | 0b0111);
        derivedKeyBytes[32] = 0b01011110;
        derivedKeyBytes[33] = 0b10101110;
        derivedKeyBytes[34] = 0b00101111;

        string derivedSecurityKey = GenerateBase64KeyHelper(derivedChecksumSeed.Value,
                                                            (uint)derivedKeyBytes.Length,
                                                            signature,
                                                            encodeForUrl: false,
                                                            derivedKeyBytes);

        return derivedSecurityKey;
    }

    /// <summary>
    /// Generate an identifiable secret with a URL-compatible format (replacing all '+'
    /// characters with '-' and all '/' characters with '_') and eliding all padding
    /// characters (unless the caller chooses to retain them). Strictly speaking, only
    /// the '+' character is incompatible for tokens expressed as a query string
    /// parameter. For this case, however, replacing the '/ character as well allows
    /// for a full 64-character alphabet that can be decoded by standard API in .NET, 
    /// Go, etc.
    /// </summary>
    /// <param name="checksumSeed">A seed value that initializes the Marvin checksum algorithm.</param>
    /// <param name="keyLengthInBytes">The size of the secret in bytes.</param>
    /// <param name="base64EncodedSignature">The signature that will be encoded in the identifiable secret. 
    /// This string must only contain valid URL-safe base64-encoding characters.</param>
    /// <param name="elidePadding">A boolean value that will remove the padding when true.</param>
    /// <returns>A generated identifiable key expressed as a URL-safe base64-encoded value.</returns>
    public static string GenerateUrlSafeBase64Key(ulong checksumSeed,
                                                  uint keyLengthInBytes,
                                                  string base64EncodedSignature,
                                                  bool elidePadding = false)
    {
        byte[] randomBytes = new byte[(int)keyLengthInBytes];

        s_generator ??= RandomNumberGenerator.Create();
        s_generator.GetBytes(randomBytes);

        string secret = GenerateBase64KeyHelper(checksumSeed,
                                                keyLengthInBytes,
                                                base64EncodedSignature,
                                                encodeForUrl: true,
                                                randomBytes);

        // The '=' padding must be encoded in some URL contexts but can be 
        // directly expressed in others, such as a query string parameter.
        // Additionally, some URL Base64 Encoders (such as Azure's 
        // Base64UrlEncoder class) expect padding to be removed while
        // others (such as Go's Base64.URLEncoding helper) expect it to
        // exist. We therefore provide an option to express it or not.
        return elidePadding ? secret.TrimEnd('=') : secret;
    }

    /// <summary>
    /// <param name="checksumSeed">A seed value that initializes the Marvin checksum algorithm.</param>
    /// <param name="keyLengthInBytes">The size of the secret in bytes.</param>
    /// <param name="base64EncodedSignature">The signature that will be encoded in the identifiable secret. 
    /// This string must only contain valid base64-encoding characters.</param>
    /// </summary>
    /// <returns>A generated identifiable key expressed as a base64-encoded value.</returns>
    public static string GenerateStandardBase64Key(ulong checksumSeed,
                                                   uint keyLengthInBytes,
                                                   string base64EncodedSignature)
    {
        byte[] randomBytes = new byte[(int)keyLengthInBytes];

        s_generator ??= RandomNumberGenerator.Create();
        s_generator.GetBytes(randomBytes);

        return GenerateBase64KeyHelper(checksumSeed,
                                       keyLengthInBytes,
                                       base64EncodedSignature,
                                       encodeForUrl: false,
                                       randomBytes);
    }

    // This helper is a primary focus of unit-testing, due to the fact it
    // contains the majority of the logic for base64-encoding scenarios.
    internal static string GenerateBase64KeyHelper(ulong checksumSeed,
                                                   uint keyLengthInBytes,
                                                   string base64EncodedSignature,
                                                   bool encodeForUrl,
                                                   byte[] randomBytes = null)
    {
        if (keyLengthInBytes > MaximumGeneratedKeySize)
        {
            throw new ArgumentException(
                "Key length must be less than 4096 bytes.",
                nameof(keyLengthInBytes));
        }

        if (keyLengthInBytes < MinimumGeneratedKeySize)
        {
            throw new ArgumentException(
                "Key length must be at least 24 bytes to provide sufficient security (>128 bits of entropy).",
                nameof(keyLengthInBytes));
        }

        if (randomBytes != null && randomBytes.Length != keyLengthInBytes)
        {
            throw new ArgumentException(
                "Specified key length did not match 'randomBytes' length.",
                nameof(keyLengthInBytes));
        }

        ValidateBase64EncodedSignature(base64EncodedSignature, encodeForUrl);

        // NOTE: 'identifiable keys' help create security value by encoding signatures in
        //       both the binary and encoded forms of the token. Because of the minimum
        //       key length enforcement immediately above, this code DOES NOT COMPROMISE
        //       THE ACTUAL SECURITY OF THE KEY. The current SDL standard recommends 192
        //       bits of entropy. The minimum threshold is 128 bits.
        //
        //       Encoding signatures both at the binary level and within the base64-encoded
        //       version virtually eliminates false positives and false negatives in
        //       detection and enables for extremely efficient scanning. These values
        //       allow for much more stringent security controls, such as blocking keys
        //       entirely from source code, work items, etc.
        //
        // 'S' == signature byte : 'C' == checksum byte : '?' == sensitive byte
        // ????????????????????????????????????????????????????????????????????????????SSSSCCCCCC==

        if (randomBytes == null)
        {
            randomBytes = new byte[(int)keyLengthInBytes];
            s_generator ??= RandomNumberGenerator.Create();
            s_generator.GetBytes(randomBytes);
        }

        return GenerateKeyWithAppendedSignatureAndChecksum(randomBytes,
                                                           base64EncodedSignature,
                                                           checksumSeed,
                                                           encodeForUrl);
    }

    internal static void ValidateCommonAnnotatedKeySignature(string base64EncodedSignature)
    {
        const int requiredEncodedSignatureLength = 4;

        if (base64EncodedSignature?.Length != requiredEncodedSignatureLength)
        {
            throw new ArgumentException(
                "Base64-encoded signature must be 4 characters long.",
                nameof(base64EncodedSignature));
        }

        if (char.IsDigit(base64EncodedSignature[0]))
        {
            throw new ArgumentException(
                "The first character of the signature must not be a digit.");

        }

        foreach (char ch in base64EncodedSignature)
        {
            if (!IsBase62EncodingChar(ch))
            {
                throw new ArgumentException(
                    "Signature can only contain alphanumeric values.");
            }
        }

        string allUpper = base64EncodedSignature.ToUpperInvariant();
        if (base64EncodedSignature.Equals(allUpper))
        {
            return;
        }

        string allLower = base64EncodedSignature.ToLowerInvariant();
        if (base64EncodedSignature.Equals(allLower))
        {
            return;
        }

        throw new ArgumentException(
                    $"Signature characters must all upper- or all lower-case: {base64EncodedSignature}");
    }

    private static void ValidateBase64EncodedSignature(string base64EncodedSignature, bool encodeForUrl)
    {
        const int requiredEncodedSignatureLength = 4;

        if (base64EncodedSignature?.Length != requiredEncodedSignatureLength)
        {
            throw new ArgumentException(
                "Base64-encoded signature must be 4 characters long.",
                nameof(base64EncodedSignature));
        }

        foreach (char ch in base64EncodedSignature)
        {
            bool isValidChar = encodeForUrl
                ? ch.IsBase64UrlEncodingChar()
                : ch.IsBase64EncodingChar();

            if (!isValidChar)
            {
                string prefix = encodeForUrl ? "URL " : string.Empty;
                throw new ArgumentException(
                    $"Signature contains one or more illegal characters {prefix}base64-encoded characters: {base64EncodedSignature}",
                    nameof(base64EncodedSignature));
            }
        }
    }

    // The checksum is 32 bits / 4 bytes, which takes 6 base64 characters to encode.
    private const int checksumSizeInBytes = 4;
    private const int lengthOfEncodedChecksum = 6;

    public static bool ValidateChecksum(string key, ulong checksumSeed, out byte[] bytes)
    {
        try
        {
            bytes = ConvertFromBase64String(key);
        }
        catch (FormatException)
        {
            bytes = null;
            return false;
        }

        byte[] checksumBytes = new byte[4];
        Array.Copy(bytes, bytes.Length - checksumSizeInBytes, checksumBytes, 0, checksumSizeInBytes);

        int expectedChecksum = BitConverter.ToInt32(checksumBytes, 0);
        int actualChecksum = Marvin.ComputeHash32(bytes, checksumSeed, 0, bytes.Length - checksumSizeInBytes);

        if (actualChecksum == expectedChecksum)
        {
            return true;
        }

        if (key.Length != LongFormEncodedCommonAnnotatedKeySize &&
            key.Length != StandardEncodedCommonAnnotatedKeySize)
        {
            return false;
        }

        int encodedChecksumLength = key.Length == LongFormEncodedCommonAnnotatedKeySize ? 8 : 4;
        string encodedChecksum = key.Substring(key.Length - encodedChecksumLength).Trim('=');

        checksumBytes = BitConverter.GetBytes(actualChecksum);
        string computedEncodedChecksum = GetBase62EncodedChecksum(checksumBytes).Trim('=');

        return computedEncodedChecksum.StartsWith(encodedChecksum);
    }

    /// <summary>
    /// Validate if the identifiable secret contains a valid format.
    /// </summary>
    /// <param name="key">A base64-encoded identifiable secret, encoded using the standard base64-alphabet or a URL friendly alternate.</param>
    /// <param name="checksumSeed">The seed used to initialize the Marvin32 checksum algorithm.</param>
    /// <param name="base64EncodedSignature">A fixed signature that should immediately precede the checksum in the encoded secret.</param>
    /// <param name="encodeForUrl">'true' if the secret was encoded for URLs (replacing '+' and '/' characters and eliminating any padding).</param>
    /// <returns>True if the provided key contains the specified signature and contains a checksum that matches the checksum of the key
    /// computed using the specified checksum seed and false otherwise. Also returns false in cases where the input data is invalid (e.g., if it can't be base64-decoded).</returns>
    [ExcludeFromCodeCoverage]
    public static bool TryValidateBase64Key(string key, ulong checksumSeed, string base64EncodedSignature, bool encodeForUrl = false)
    {
        try
        {
            return ValidateBase64Key(key, checksumSeed, base64EncodedSignature, encodeForUrl);
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    /// <summary>
    /// Validate if the identifiable secret contains a valid format.
    /// </summary>
    /// <param name="key">A base64-encoded identifiable secret, encoded using the standard base64-alphabet or a URL friendly alternate.</param>
    /// <param name="checksumSeed">The seed used to initialize the Marvin32 checksum algorithm.</param>
    /// <param name="base64EncodedSignature">A fixed signature that should immediately precede the checksum in the encoded secret.</param>
    /// <param name="encodeForUrl">'true' if the secret was encoded for URLs (replacing '+' and '/' characters and eliminating any padding).</param>
    /// <returns>True if the provided key contains the specified signature and contains a checksum that matches the checksum of the key computed using the specified checksum seed and false otherwise.</returns>
    public static bool ValidateBase64Key(string key, ulong checksumSeed, string base64EncodedSignature, bool encodeForUrl = false)
    {
        ValidateBase64EncodedSignature(base64EncodedSignature, encodeForUrl);

        if (!ValidateChecksum(key, checksumSeed, out _))
        {
            return false;
        }

        if (HasIncorrectSpecialCharacters(key, encodeForUrl))
        {
            return false;
        }

        int padding = CountPaddingCharacters(key);
        int signatureOffset = key.Length - padding - lengthOfEncodedChecksum - base64EncodedSignature.Length;
        return base64EncodedSignature == key.Substring(signatureOffset, base64EncodedSignature.Length);
    }

    private static readonly char[] s_specialCharsForBase64Url = ['-', '_'];
    private static readonly char[] s_specialCharsForBase64Standard = ['+', '/'];

    private static bool HasIncorrectSpecialCharacters(string key, bool encodeForUrl)
    {
        char[] incorrectSpecialChars = encodeForUrl ? s_specialCharsForBase64Standard : s_specialCharsForBase64Url;
        return key.IndexOfAny(incorrectSpecialChars) >= 0;
    }

    private static int CountPaddingCharacters(string s)
    {
        int padding = 0;

        for (int i = s.Length - 1; i >= 0; i--)
        {
            if (s[i] == '=')
            {
                padding++;
            }
            else
            {
                break;
            }
        }

        return padding;
    }

    private static int ComputeSpilloverBitsIntoFinalEncodedCharacter(int countOfBytes)
    {
        // Retrieve padding required to maintain the 6-bit alignment
        // that allows the base64-encoded signature to render.
        // 
        // First we compute the # of bits of total information to encode.
        // Next, using the modulo operator, we determine the number of 
        // 'spillover' bits that will flow into, but not not completely 
        // fill, the final 6-bit encoded value. 
        const int bitsInBytes = 8;
        const int bitsInBase64Character = 6;

        return (countOfBytes * bitsInBytes) % bitsInBase64Character;
    }

    private static string GenerateKeyWithAppendedSignatureAndChecksum(byte[] keyValue,
                                                                      string base64EncodedSignature,
                                                                      ulong checksumSeed,
                                                                      bool encodeForUrl)
    {
        int keyLengthInBytes = keyValue.Length;
        int checksumOffset = keyLengthInBytes - 4;
        int signatureOffset = checksumOffset - 4;

        // Compute a signature that will render consistently when
        // base64-encoded. This potentially requires consuming bits
        // from the byte that precedes the signature (to keep data
        // aligned on a 6-bit boundary, as required by base64).
        byte signaturePrefixByte = keyValue[signatureOffset];

        byte[] signatureBytes = GetBase64EncodedSignatureBytes(keyLengthInBytes,
                                                               base64EncodedSignature,
                                                               signaturePrefixByte);
        signatureBytes.CopyTo(keyValue, signatureOffset);

        // We will disregard the final four bytes of the randomized input, as 
        // these bytes will be overwritten with the checksum, and therefore
        // aren't relevant to that computation.
        const int sizeOfChecksumInBytes = sizeof(uint);

        int checksum = Marvin.ComputeHash32(keyValue, checksumSeed, 0, keyValue.Length - sizeOfChecksumInBytes);

        byte[] checksumBytes = BitConverter.GetBytes(checksum);
        checksumBytes.CopyTo(keyValue, checksumOffset);

        return ConvertToBase64String(keyValue, encodeForUrl);
    }

    internal static byte[] GetBase64EncodedSignatureBytes(int keyLengthInBytes,
                                                          string base64EncodedSignature,
                                                          byte signaturePrefixByte)
    {
        byte[] signatureBytes = ConvertFromBase64String(base64EncodedSignature);

        uint signature = (uint)signaturePrefixByte << 24;

        // Compute the padding or 'spillover' into the final base64-encoded secret
        // for the random portion of the token, which is our data array minus
        // 7 bytes (3 bytes for the fixed signature, 4 bytes for the checksum).
        int padding = ComputeSpilloverBitsIntoFinalEncodedCharacter(keyLengthInBytes - 7);

        uint mask = uint.MaxValue;

        switch (padding)
        {
            case 2:
                {
                    // Clear two bits where the signature will be right-shifted
                    // to align on the base64-encoded 6-bit boundary.
                    mask = 0xfcffffff;
                    break;
                }

            case 4:
                {
                    // Clear four bits where the signature will be right-shifted
                    // to remain aligned with base64-encoded 6-bit boundary.
                    mask = 0xf0ffffff;
                    break;
                }
        }

        signature &= mask;

        signature |= (uint)signatureBytes[0] << (16 + padding);
        signature |= (uint)signatureBytes[1] << (8 + padding);
        signature |= (uint)signatureBytes[2] << (0 + padding);

        signatureBytes = BitConverter.GetBytes(signature);

        if (BitConverter.IsLittleEndian)
        {
            Array.Reverse(signatureBytes);
        }

        return signatureBytes;
    }

    internal static string TransformToUrlSafeEncoding(string base64EncodedText)
    {
        return base64EncodedText.Replace('+', '-').Replace('/', '_');
    }

    internal static string TransformToStandardEncoding(string urlSafeBase64EncodedText)
    {
        return urlSafeBase64EncodedText.Replace('-', '+').Replace('_', '/');
    }

    internal static string RetrievePaddingForBase64EncodedText(string text)
    {
        int paddingCount = 4 - (text.Length % 4);

        if (string.IsNullOrEmpty(text))
        {
            return string.Empty;
        }

        char lastChar = text[text.Length - 1];
        return (lastChar != '=' && paddingCount < 3)
            ? new string('=', paddingCount)
            : string.Empty;
    }

    internal static byte[] ConvertFromBase64String(string text)
    {
        text = TransformToStandardEncoding(text);
        text += RetrievePaddingForBase64EncodedText(text);
        byte[] result;

        result = Convert.FromBase64String(text);

        return result;
    }

    private static string ConvertToBase64String(byte[] data, bool encodeForUrl)
    {
        string text = Convert.ToBase64String(data);

        if (encodeForUrl)
        {
            text = TransformToUrlSafeEncoding(text);
        }

        return text;
    }
}
