// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Microsoft.Security.Utilities;

#pragma warning disable SA1202  // 'public' members should come before 'private' members.
#pragma warning disable SA1203  // Constant fields should appear before non-constant fields.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

public static class WellKnownRegexPatterns
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

        foreach (RegexPattern detection in UnclassifiedPotentialSecurityKeys)
        {
            yield return detection;
        }
    }

    public static IEnumerable<RegexPattern> PreciselyClassifiedSecurityKeys { get; } = HighConfidenceSecurityModelsIterator();

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

    public static IEnumerable<RegexPattern> UnclassifiedPotentialSecurityKeys { get; } = new RegexPattern[]
    {
        new GenericJwt(),
        new LooseSasSecret(),
        new Unclassified32ByteBase64String(),
        new Unclassified64ByteBase64String(),
        new Unclassified16ByteHexadecimalString(),
    };

    public static IEnumerable<RegexPattern> HighConfidenceMicrosoftSecurityModels { get; } = new RegexPattern[]
    {
        //new CommonAnnotatedSecurityKey(),
        new AadClientAppIdentifiableCredentials(),
        new AzureFunctionIdentifiableKey(),
        new AzureSearchIdentifiableQueryKey(),
        new AzureSearchIdentifiableAdminKey(),
        new AzureRelayIdentifiableKey(),
        new AzureEventHubIdentifiableKey(),
        new AzureServiceBusIdentifiableKey(),
        new AzureIotHubIdentifiableKey(),
        new AzureIotDeviceIdentifiableKey(),
        new AzureIotDeviceProvisioningIdentifiableKey(),
        new AzureStorageAccountIdentifiableKey(),
        new AzureCosmosDBIdentifiableKey(),
        new AzureBatchIdentifiableKey(),
        new AzureMLWebServiceClassicIdentifiableKey(),
        new AzureApimIdentifiableDirectManagementKey(),
        new AzureApimIdentifiableSubscriptionKey(),
        new AzureApimIdentifiableGatewayKey(),
        new AzureApimIdentifiableRepositoryKey(),
        new AzureCacheForRedisIdentifiableKey(),
        new AzureContainerRegistryIdentifiableKey(),
        new NuGetApiKey(),
        new AadClientAppLegacyCredentials32(),      // SEC101/101
        new AadClientAppLegacyCredentials34(),      // SEC101/101
        new AdoPat(),                               // SEC101/102
        new AzureCosmosDBLegacyCredentials(),       // SEC101/104
        new AzureStorageAccountLegacyCredentials(), // SEC101/106
        new AzureMessageLegacyCredentials(),
        new AzureDatabricksPat(),
        new AzureEventGridIdentifiableKey(),
    };

    public static IEnumerable<RegexPattern> HighConfidenceThirdPartySecurityModels { get; } = new List<RegexPattern>
    {
        new NpmAuthorKey(),
        new SecretScanningSampleToken(),
    };


    public static string RandomUrlUnreserved(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseUrlUnreserved : UrlUnreserved, count);
    }

    public static string RandomLowercase(int count, bool sparse = false)
    {
        return GenerateString(sparse ? SparseLowercase : Lowercase, count);
    }

    public static string RandomHexadecimal(int count)
    {
        return GenerateString(Hexadecimal, count);
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

    // These test character sets, by design, do not follow their strict definition.
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
    public const string Hexadecimal = $"{Digit}abcdef";
    public const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    public const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Alpha = $"{Lowercase}{Uppercase}";
    public const string Base62 = $"{Alpha}{Digit}";
    public const string Base64 = $"{Base62}+/";
    public const string UrlSafeBase64 = $"{Base62}-_";
    public const string UrlUnreserved = $"{Base62}-_~.";

    private const string End = "$";
    private const string Start = "^";

    public const string RegexEncodedUrlSafeBase64 = @$"{Base62}\-_";
    public const string RegexEncodedUrlUnreserved = @$"{RegexEncodedUrlSafeBase64}~.";
    public const string PrefixUrlSafeBase64 = $"({Start}|[^{RegexEncodedUrlSafeBase64}])";
    public const string SuffixUrlSafeBase64 = $"([^{RegexEncodedUrlSafeBase64}]|{End})";

    public const string PrefixUrlUnreserved = $"({Start}|[^{RegexEncodedUrlUnreserved}+/=])";
    public const string SuffixUrlUnreserved = $"([^{RegexEncodedUrlUnreserved}+/=]|{End})";
    public const string PrefixBase62 = $"({Start}|[^{Base62}])";
    public const string SuffixBase62 = $"([^{Base62}]|{End})";
    public const string PrefixAllBase64 = $"({Start}|[^{Base64}-_=])";
    public const string SuffixAllBase64 = $"([^{Base64}-_=]|{End})";
    public const string PrefixHexadecimal = $"({Start}|[^{Hexadecimal}])";
    public const string SuffixHexadecimal = $"([^{Hexadecimal}]|{End})";
}
