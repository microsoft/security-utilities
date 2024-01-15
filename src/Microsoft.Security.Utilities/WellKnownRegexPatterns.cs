// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Security.Utilities;

#pragma warning disable IDE1006 // Naming rule violation.
#pragma warning disable R9A015  // Use R9 ArgumentOutOfRangeException helper.
#pragma warning disable R9A044  // Assign array of literal values to static field for improved performance.
#pragma warning disable S103    // Split this long line.
#pragma warning disable S109    // Assign this magic number to a variable or constant.
#pragma warning disable S3995   // Convert this return type to 'System.Uri'.
#pragma warning disable SA1202  // 'public' members should come before 'private' members.
#pragma warning disable SA1203  // Constant fields should appear before non-constant fields.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

internal static class WellKnownRegexPatterns
{
    [ThreadStatic]
    private static StringBuilder s_stringBuilder;

    public static IEnumerable<RegexPattern> SecretStoreClassificationDetections { get; } = SecretStoreClassificationDetectionsIterator();

    public static IEnumerable<RegexPattern> SecretStoreClassificationDetectionsIterator()
    {
        foreach (RegexPattern detection in HighConfidenceSecurityModelsIterator())
        {
            yield return detection;
        }

        foreach (RegexPattern detection in LowConfidenceMicrosoftSecurityModels)
        {
            yield return detection;
        }
    }

    public static IEnumerable<RegexPattern> HighConfidenceSecurityModels { get; } = HighConfidenceSecurityModelsIterator();

    public static IEnumerable<RegexPattern> HighConfidenceSecurityModelsIterator()
    {
        foreach (RegexPattern detection in HighConfidenceMicrosoftSecurityModels)
        {
            yield return detection;
        }

        foreach (RegexPattern detection in HighConfidenceThirdPartySecurityModels)
        {
            yield return detection;
        }
    }

    public static IEnumerable<RegexPattern> LowConfidenceMicrosoftSecurityModels { get; } = new[]
    {
        LegacyAadClientAppSecret(),
        new Unclassified32ByteBase64String(),
        new Unclassified64ByteBase64String(),
    };

    public static IEnumerable<RegexPattern> HighConfidenceMicrosoftSecurityModels { get; } = new[]
    {
        NuGetApiKey(),
        AadClientAppSecretCurrent(),
        AadClientAppSecretPrevious(),
        AzureFunctionIdentifiableKey(),
        new AzureSearchIdentifiableKeys(),
        new Azure64ByteIdentifiableKeys(),
        new Azure32ByteIdentifiableKeys(),
        AzureCacheForRedisIdentifiableKey(),
        AzureContainerRegistryIdentifiableKey(),
    };

    public static IEnumerable<RegexPattern> HighConfidenceThirdPartySecurityModels { get; } = new List<RegexPattern>
    {
        NpmAuthorKey(),
    };

    public static RegexPattern LegacyAadClientAppSecret()
    {
        return new("SEC101/156",
                   nameof(LegacyAadClientAppSecret),
                   DetectionMetadata.ObsoleteFormat | DetectionMetadata.HighEntropy,
                   $"{PrefixUrlUnreserved}(?<refine>[{RegexEncodedUrlUnreserved}]{{34}}){SuffixUrlUnreserved}",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[] { $"{RandomUrlUnreserved(34)}" });
    }

    // AAD client app, most recent two versions.
    public static RegexPattern AadClientAppSecretCurrent()
    {
        return new("SEC101/156",
                   "AadClientAppSecret",
                   DetectionMetadata.Identifiable,
                   $"{PrefixUrlUnreserved}(?<refine>[{RegexEncodedUrlUnreserved}]{{3}}8Q~[{RegexEncodedUrlUnreserved}]{{34}}){SuffixUrlUnreserved}",
                   TimeSpan.FromDays(365 * 2),
                   new HashSet<string>(new[] { "8Q~" }),
                   sampleGenerator: () => new[] { $"{RandomUrlUnreserved(3)}8Q~{RandomUrlUnreserved(34)}" });
    }

    public static RegexPattern AadClientAppSecretPrevious()
    {
        return new("SEC101/156",
            "AadClientAppSecret",
            DetectionMetadata.HighConfidence | DetectionMetadata.HighEntropy,
            $"{PrefixUrlUnreserved}(?<refine>[{RegexEncodedUrlUnreserved}]{{3}}7Q~[{RegexEncodedUrlUnreserved}]{{31}}){SuffixUrlUnreserved}",
            TimeSpan.FromDays(365 * 2),
            new HashSet<string>(new[] { "7Q~" }),
            sampleGenerator: () => new[] { $"{RandomUrlUnreserved(3)}7Q~{RandomUrlUnreserved(31)}" });
    }

    public static RegexPattern AzureFunctionIdentifiableKey()
    {
        return new("SEC101/158",
                   nameof(AzureFunctionIdentifiableKey),
                   DetectionMetadata.Identifiable,
                   @$"{PrefixUrlSafeBase64}(?<refine>[{RegexEncodedUrlSafeBase64}]{{44}}AzFu[{RegexEncodedUrlSafeBase64}]{{5}}[AQgw]==){SuffixUrlSafeBase64}",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[]
                   {
                       IdentifiableSecrets.GenerateUrlSafeBase64Key(IdentifiableMetadata.AzureFunctionKeyChecksumSeed, 40, IdentifiableMetadata.AzureFunctionSignature),
                       IdentifiableSecrets.GenerateUrlSafeBase64Key(IdentifiableMetadata.AzureFunctionSystemKeyChecksumSeed, 40, IdentifiableMetadata.AzureFunctionSignature),
                       IdentifiableSecrets.GenerateUrlSafeBase64Key(IdentifiableMetadata.AzureFunctionMasterKeyChecksumSeed, 40, IdentifiableMetadata.AzureFunctionSignature),
                   });
    }

    public static RegexPattern AzureContainerRegistryIdentifiableKey()
    {
        return new("SEC101/176",
                   nameof(AzureContainerRegistryIdentifiableKey),
                   DetectionMetadata.Identifiable,
                   $@"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{42}}\+ACR[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[]
                   {
                       IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureContainerRegistryChecksumSeed, 39, IdentifiableMetadata.AzureContainerRegistrySignature),
                   });
    }

    public static RegexPattern AzureCacheForRedisIdentifiableKey()
    {
        return new("SEC101/154",
                   nameof(AzureCacheForRedisIdentifiableKey),
                   DetectionMetadata.Identifiable,
                   $@"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base62}]{{33}}{IdentifiableMetadata.AzureCacheForRedisSignature}[A-P][{WellKnownRegexPatterns.Base62}]{{5}}=){WellKnownRegexPatterns.SuffixAllBase64}",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[]
                   {
                       IdentifiableSecrets.GenerateStandardBase64Key(
                            IdentifiableMetadata.AzureCacheForRedisChecksumSeed, 32, IdentifiableMetadata.AzureCacheForRedisSignature)
                                .Replace('/', 'F')
                                .Replace('+', 'P')
                   });
    }

    public static RegexPattern NuGetApiKey()
    {
        return new("SEC101/031",
                   nameof(NuGetApiKey),
                   DetectionMetadata.HighConfidence | DetectionMetadata.HighEntropy,
                   "(^|[^0-9a-z])(?<refine>oy2[a-p][0-9a-z]{15}[aq][0-9a-z]{11}[eu][bdfhjlnprtvxz357][a-p][0-9a-z]{11}[aeimquy4])([^aeimquy4]|$)",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[] { $"oy2a{RandomLowercase(15)}a{RandomLowercase(11)}e7a{RandomLowercase(11)}a" });
    }

    public static RegexPattern NpmAuthorKey()
    {
        return new("SEC101/050",
                   nameof(NpmAuthorKey),
                   DetectionMetadata.HighConfidence | DetectionMetadata.HighEntropy,
                   @$"{PrefixBase62}(?<refine>npm_[{Base62}]{{36}}){SuffixBase62}",
                   TimeSpan.FromDays(365 * 2),
                   sampleGenerator: () => new[] { $"npm_{RandomBase62(36)}" });
    }

    public static string RandomUrlUnreserved(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseUrlUnreserved : UrlUnreserved, count);
    }

    public static string RandomLowercase(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseLowercase : Lowercase, count);
    }

    public static string RandomBase62(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseBase62 : Base62, count);
    }

    public static string RandomBase64(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseBase64 : Base64, count);
    }

    public static string GenerateString(string alphabet, int count)
    {
        alphabet = alphabet ?? throw new ArgumentNullException(nameof(alphabet));

        s_stringBuilder ??= new StringBuilder();

        s_stringBuilder.Length = 0;
        for (int i = 0; i < count; i++)
        {
            using var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[1];
            rng.GetBytes(bytes);
            int index = bytes[0] % alphabet.Length;
            char ch = alphabet[index];
            _ = s_stringBuilder.Append(ch);
        }

        string result = s_stringBuilder.ToString();
        s_stringBuilder.Length = 0;
        return result;
    }

    // These test character sets, by design, do not follow their strict defintion.
    // The reason is that we want the generated test samples (for some scenarios)
    // to generate a key that is fairly easily identified as a test sample.
    // These generated keys will satisfy as preliminary regex detection but will
    // tend to fail a post-processing steps (that validates shannon entropy or
    // other heuristics that verify randomness of the pattern).
    private const string SparseDigit = "9";
    private const string SparseLowercase = "mf";
    private const string sparseUppercase = "MF";
    private const string SparseAlpha = $"{SparseLowercase}{sparseUppercase}";
    private const string SparseBase62 = $"{SparseAlpha}{SparseDigit}";
    private const string SparseBase64 = $"{SparseBase62}+"; // Forward slash elided.
    private const string SparseUrlSafeBase64 = $"{SparseBase62}-"; // Underscore elided.
    private const string SparseUrlUnreserved = $"{SparseUrlSafeBase64}~"; // Period elided.

    public const string Digit = "1234567890";
    public const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    public const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Alpha = $"{Lowercase}{Uppercase}";
    public const string Base62 = $"{Alpha}{Digit}";
    public const string Base64 = $"{Base62}+/";
    public const string UrlSafeBase64 = $"{Base62}-_";
    public const string UrlUnreserved = $"{Base62}-_~.";

    private const string End = "$";
    private const string Start = "^";

    private const string RegexEncodedUrlSafeBase64 = @$"{Base62}\-_";
    private const string RegexEncodedUrlUnreserved = @$"{RegexEncodedUrlSafeBase64}~.";
    public const string PrefixUrlSafeBase64 = $"({Start}|[^{RegexEncodedUrlSafeBase64}])";
    public const string SuffixUrlSafeBase64 = $"([^{RegexEncodedUrlSafeBase64}]|{End})";

    public const string PrefixUrlUnreserved = $"({Start}|[^{RegexEncodedUrlUnreserved}+/=])";
    public const string SuffixUrlUnreserved = $"([^{RegexEncodedUrlUnreserved}+/=]|{End})";
    public const string PrefixBase62 = $"({Start}|[^{Base62}])";
    public const string SuffixBase62 = $"([^{Base62}]|{End})";
    public const string PrefixAllBase64 = $"({Start}|[^{Base64}-_=])";
    public const string SuffixAllBase64 = $"([^{Base64}-_=]|{End})";
}
