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
    public const string CommonAnnotatedKeyRegexPattern = "[A-Za-z0-9]{52}JQQJ99[A-Za-z0-9][A-L][A-Za-z0-9]{16}[A-Za-z][A-Za-z0-9]{7}([A-Za-z0-9]{2}==)?";

    public static readonly Regex CommonAnnotatedKeyRegex = new(CommonAnnotatedKeyRegexPattern, RegexDefaults.DefaultOptionsCaseSensitive);

    public static uint MaximumGeneratedKeySize => 4096;

    public static uint MinimumGeneratedKeySize => 24;

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

    public static bool TryValidateCommonAnnotatedKey(string key,
                                                     ulong checksumSeed,
                                                     string base64EncodedSignature,
                                                     bool customerManagedKey)
    {
        base64EncodedSignature = customerManagedKey
                ? base64EncodedSignature.ToUpperInvariant()
                : base64EncodedSignature.ToLowerInvariant();

        string componentToChecksum = key.Substring(0, key.Length - 4);
        string checksumText = key.Substring(key.Length - 4);

        byte[] keyBytes = Convert.FromBase64String(componentToChecksum);

#if NET5_0_OR_GREATER
        var checksumInput = new ReadOnlySpan<byte>(keyBytes).Slice(0, keyBytes.Length);
        int checksum = Marvin.ComputeHash32(checksumInput, checksumSeed);
#else
        int checksum = Marvin.ComputeHash32(keyBytes, checksumSeed, 0, keyBytes.Length);
#endif

        byte[] checksumBytes = BitConverter.GetBytes(checksum);
        byte[] truncatedChecksumBytes = new byte[3];

        truncatedChecksumBytes[0] = checksumBytes[0];
        truncatedChecksumBytes[1] = checksumBytes[1];
        truncatedChecksumBytes[2] = checksumBytes[2];

        string encoded = Convert.ToBase64String(truncatedChecksumBytes);

        return encoded == checksumText;
    }

    /// <summary>
    /// Generate a <see cref="ulong"/> checksum seed from a string literal that is 8 characters
    /// long and ends with at least one digit, e.g., 'ReadKey0', 'RWSeed00', etc. The checksum
    /// seed is used to initialize the Marvin32 algorithm to watermark a specific class of
    /// generated security keys.
    /// </summary>
    /// <param name="versionedKeyKind">A readable name that identifies a specific set of generated keys with at least one trailing digit in the name.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public static ulong ComputeChecksumSeed(string versionedKeyKind)
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


    public static string GenerateCommonAnnotatedKey(ulong checksumSeed,
                                                    string base64EncodedSignature,
                                                    bool customerManagedKey,
                                                    byte[] platformReserved,
                                                    byte[] providerReserved)
    {
        return GenerateCommonAnnotatedTestKey(checksumSeed,
                                              base64EncodedSignature,
                                              customerManagedKey,
                                              platformReserved,
                                              providerReserved,
                                              testChar: null);
    }

    public static string GenerateCommonAnnotatedTestKey(ulong checksumSeed,
                                                    string base64EncodedSignature,
                                                    bool customerManagedKey,
                                                    byte[] platformReserved,
                                                    byte[] providerReserved,
                                                    char? testChar)
    {
        const int platformReservedLength = 9; 
        const int providerReservedLength = 3;

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
            platformReserved =  new byte[platformReservedLength];
        }

        if (providerReserved == null)
        {
            providerReserved = new byte[providerReservedLength];
        }

        base64EncodedSignature = customerManagedKey 
                ? base64EncodedSignature.ToUpperInvariant()
                : base64EncodedSignature.ToLowerInvariant();

        string key = null;

        while (true)
        {
            int keyLengthInBytes = 66;
            byte[] keyBytes = new byte[keyLengthInBytes];

            if (testChar == null)
            {
                using var generator = RandomNumberGenerator.Create();
                generator.GetBytes(keyBytes, 0, (int)keyLengthInBytes);

                key = keyBytes.ToBase62().Substring(0, 86);
                key = $"{key}==";
            }
            else
            {
                key = $"{new string(testChar!.Value, 86)}==";
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
            byte yearsSince2024 = (byte)(DateTime.UtcNow.Year - 2024);
            byte zeroIndexedMonth = (byte)(DateTime.UtcNow.Month - 1);

            int? metadata = (61 << 18) | (61 << 12) | (yearsSince2024 << 6) | zeroIndexedMonth;
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

#if NET5_0_OR_GREATER
            var checksumInput = new ReadOnlySpan<byte>(keyBytes).Slice(0, keyBytes.Length - 4);
            int checksum = Marvin.ComputeHash32(checksumInput, checksumSeed);
#else
            int checksum = Marvin.ComputeHash32(keyBytes, checksumSeed, 0, keyBytes.Length - 4);
#endif

            byte[] checksumBytes = BitConverter.GetBytes(checksum);

            checksumBytes = BitConverter.GetBytes(checksum);

            keyBytes[keyBytes.Length - 4] = checksumBytes[0];
            keyBytes[keyBytes.Length - 3] = checksumBytes[1];
            keyBytes[keyBytes.Length - 2] = checksumBytes[2];
            keyBytes[keyBytes.Length - 1] = checksumBytes[3];

            key = Convert.ToBase64String(keyBytes);

            if (!key.Contains("+") && !key.Contains("/"))
            {
                key = key.Substring(0, key.Length - 4);
                break;
            }
            else if (testChar != null)
            {
                // We could not produce a valid test key given the current signature,
                // checksum seed, reserved bits and specified test character.
                key = null;
                break;
            }
        }

        return key;
    }

    public static string ComputeDerivedSymmetricKey(string key, ulong checksumSeed, string textToSign, bool encodeForUrl = false)
    {
        string signature = key.Trim('=');
        signature = signature.Substring(signature.Length - 10, 4);

        if (!TryValidateBase64Key(key, checksumSeed, signature, encodeForUrl))
        {
            throw new ArgumentException("The provided key is not a valid identifiable secret.");
        }

        string derivedKey;
        byte[] keyBytes = Convert.FromBase64String(key);

        using var hmac = new HMACSHA256(keyBytes);
        byte[] hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(textToSign));

        byte[] derivedKeyBytes = new byte[42];
        Array.Copy(hashBytes, derivedKeyBytes, hashBytes.Length);

        derivedKeyBytes[31] = (byte)((derivedKeyBytes[31] & 0xC0) | 0b0111);
        derivedKeyBytes[32] = 0b01011110;
        derivedKeyBytes[33] = 0b10101110;
        derivedKeyBytes[34] = 0b00101111;

        derivedKey = GenerateBase64KeyHelper(checksumSeed,
                                             (uint)derivedKeyBytes.Length,
                                             signature,
                                             encodeForUrl: false,
                                             derivedKeyBytes);

        return derivedKey;
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

        using var generator = RandomNumberGenerator.Create();
        generator.GetBytes(randomBytes, 0, (int)keyLengthInBytes);

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

        using var generator = RandomNumberGenerator.Create();
        generator.GetBytes(randomBytes, 0, (int)keyLengthInBytes);

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
            using var generator = RandomNumberGenerator.Create();
            generator.GetBytes(randomBytes, 0, (int)keyLengthInBytes);
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

        foreach (char ch in base64EncodedSignature)
        {
            if (!IsBase62EncodingChar(ch))
            {
                throw new ArgumentException(
                    "Signature can only contain alphabetic or numeric values.");
            }
        }
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

        const int checksumSizeInBytes = sizeof(uint);

#if NET6_0_OR_GREATER
            var bytes = new ReadOnlySpan<byte>(ConvertFromBase64String(key));
            int expectedChecksum = BitConverter.ToInt32(bytes.Slice(bytes.Length - checksumSizeInBytes, checksumSizeInBytes).ToArray(), 0);
            int actualChecksum = Marvin.ComputeHash32(bytes.Slice(0, bytes.Length - checksumSizeInBytes), checksumSeed);
#else
        byte[] bytes = ConvertFromBase64String(key);
        int expectedChecksum = BitConverter.ToInt32(bytes, bytes.Length - checksumSizeInBytes);
        int actualChecksum = Marvin.ComputeHash32(bytes, checksumSeed, 0, bytes.Length - checksumSizeInBytes);
#endif

        if (actualChecksum != expectedChecksum)
        {
            return false;
        }

        // Compute the padding or 'spillover' into the final base64-encoded secret
        // for the random portion of the token, which is our data array minus
        // the bytes allocated for the checksum (4) and fixed signature (3). Every
        // base64-encoded character comprises 6 bits and so we can compute the 
        // underlying bytes for this data by the following computation:
        int signatureSizeInBytes = base64EncodedSignature.Length * 6 / 8;
        int padding = ComputeSpilloverBitsIntoFinalEncodedCharacter(bytes.Length - signatureSizeInBytes - checksumSizeInBytes);

        // Moving in the other direction, we can compute the encoded length of the checksum
        // calculating the # of bits for the checksum, and diving this value by 6 to 
        // determine the # of base64-encoded characters. Strictly speaking, for a 4-byte value,
        // the Ceiling computation isn't required, as there will be no remainder for this
        // value (4 * 8 / 6).
        int lengthOfEncodedChecksum = (int)Math.Ceiling(checksumSizeInBytes * 8 / 6D);

        string equalsSigns = string.Empty;
#if NETCOREAPP3_1_OR_GREATER
        int equalsSignIndex = key.IndexOf('=', StringComparison.Ordinal);
#else
        int equalsSignIndex = key.IndexOf('=');
#endif
        int prefixLength = key.Length - lengthOfEncodedChecksum - base64EncodedSignature.Length;
        string pattern = string.Empty;

        if (equalsSignIndex > -1)
        {
            equalsSigns = key.Substring(equalsSignIndex);
            prefixLength = equalsSignIndex - lengthOfEncodedChecksum - base64EncodedSignature.Length;
        }

        string trimmedKey = key.Trim('=');
        int signatureOffset = trimmedKey.Length - lengthOfEncodedChecksum - base64EncodedSignature.Length;
        if (base64EncodedSignature != trimmedKey.Substring(signatureOffset, base64EncodedSignature.Length))
        {
            return false;
        }

        char lastChar = trimmedKey[trimmedKey.Length - 1];
        char firstChar = trimmedKey[trimmedKey.Length - lengthOfEncodedChecksum];

        string specialChars = encodeForUrl ? "\\-_" : "\\/+";
        string secretAlphabet = $"[a-zA-Z0-9{specialChars}]";

        // We need to escape characters in the signature that are special in regex.
#if NETCOREAPP3_1_OR_GREATER
        base64EncodedSignature = base64EncodedSignature.Replace("+", "\\+", StringComparison.Ordinal);
#else
        base64EncodedSignature = base64EncodedSignature.Replace("+", "\\+");
#endif

        string checksumPrefix = string.Empty;
        string checksumSuffix = string.Empty;

        switch (padding)
        {
            case 2:
            {
                // When we are required to right-shift the fixed signatures by two
                // bits, the first encoded character of the checksum will have its
                // first two bits set to zero, limiting encoded chars to A-P.
                checksumPrefix = "[A-P]";

                // The following condition should always be true, since we 
                // have already verified the checksum earlier in this routine.
                // We explode all conditions in this check in order to
                // 'convince' VS code coverage these conditions are 
                // exhaustively covered.
                Debug.Assert(firstChar == 'A' || firstChar == 'B' ||
                             firstChar == 'C' || firstChar == 'D' ||
                             firstChar == 'E' || firstChar == 'F' ||
                             firstChar == 'G' || firstChar == 'H' ||
                             firstChar == 'I' || firstChar == 'J' ||
                             firstChar == 'K' || firstChar == 'L' ||
                             firstChar == 'M' || firstChar == 'N' ||
                             firstChar == 'O' || firstChar == 'P', $"Unexpected first character '{firstChar}.");
                break;
            }

            case 4:
            {
                // When we are required to right-shift the fixed signatures by four
                // bits, the first encoded character of the checksum will have its
                // first four bits set to zero, limiting encoded chars to A-D.
                checksumPrefix = "[A-D]";

                // The following condition should always be true, since we 
                // have already verified the checksum earlier in this routine.
                Debug.Assert(firstChar == 'A' || firstChar == 'B' ||
                             firstChar == 'C' || firstChar == 'D', $"Unexpected first character '{firstChar}.");
                break;
            }

            default:
            {
                // In this case, we have a perfect alignment between our decoded
                // signature and checksum and their encoded representation. As
                // a result, two bits of the final checksum byte will spill into
                // the final encoded character, followed by four zeros of padding.
                // This limits the possible values for the final checksum character
                // to one of A, Q, g & w.
                checksumSuffix = "[AQgw]";

                // The following condition should always be true, since we 
                // have already verified the checksum earlier in this routine.
                Debug.Assert(lastChar == 'A' || lastChar == 'Q' ||
                             lastChar == 'g' || lastChar == 'w', $"Unexpected last character '{lastChar}.");
                break;
            }
        }

        // Example patterns, URL-friendly encoding:
        //   [a-zA-Z0-9\-_]{22}XXXX[A-D][a-zA-Z0-9\-_]{5}
        //   [a-zA-Z0-9\-_]{25}XXXX[A-P][a-zA-Z0-9\\-_]{5}
        //   [a-zA-Z0-9\-_]{24}XXXX[a-zA-Z0-9\-_]{5}[AQgw]

        pattern = $"{secretAlphabet}{{{prefixLength}}}{base64EncodedSignature}{checksumPrefix}{secretAlphabet}{{5}}{checksumSuffix}{equalsSigns}";
        var regex = new Regex(pattern);
        return regex.IsMatch(key);
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

#if NET6_0_OR_GREATER
        var checksumInput = new ReadOnlySpan<byte>(keyValue).Slice(0, keyValue.Length - sizeOfChecksumInBytes);
        int checksum = Marvin.ComputeHash32(checksumInput, checksumSeed);
#else
        int checksum = Marvin.ComputeHash32(keyValue, checksumSeed, 0, keyValue.Length - sizeOfChecksumInBytes);
#endif

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
        return Convert.FromBase64String(text);
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
