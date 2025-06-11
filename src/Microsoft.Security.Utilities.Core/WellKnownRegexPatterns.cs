// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
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

    public static IReadOnlyList<RegexPattern> UnclassifiedPotentialSecurityKeys { get; } =
        CreateList(new UnclassifiedJwt(),
                   new SEC101_127_UrlCredentials(),
                   new LooseSasSecret(),
                   new OAuth2BearerToken(),
                   new Unclassified32ByteBase64String(),
                   new Unclassified64ByteBase64String(),
                   new AadClientAppLegacyCredentials34(),
                   new Pkcs12CertificatePrivateKeyBundle(),
                   new Unclassified16ByteHexadecimalString());

    public static IReadOnlyList<RegexPattern> HighConfidenceMicrosoftSecurityModels { get; } =
        CreateList(new SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey(),
                   new UnclassifiedLegacyCommonAnnotatedSecurityKey(),
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
                   new AdoLegacyPat(),
                   new AzureCosmosDBLegacyCredentials(),
                   new AzureStorageAccountLegacyCredentials(),
                   new AzureMessagingLegacyCredentials(),
                   new AzureDatabricksPat(),
                   new AzureEventGridIdentifiableKey(),
                   new AzureAppConfigurationLegacyCommonAnnotatedSecurityKey(),
                   new AzureFluidRelayLegacyCommonAnnotatedSecurityKey(),
                   new AzureEventGridLegacyCommonAnnotatedSecurityKey(),
                   new AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat(),
                   new AzureMixedRealityLegacyCommonAnnotatedSecurityKeyPat(),
                   new AzureMapsLegacyCommonAnnotatedSecurityKey(),
                   new AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey(),
                   new AzureAIServicesLegacyCommonAnnotatedSecurityKey(),
                   new AzureOpenAILegacyCommonAnnotatedSecurityKey(),
                   new AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey(),
                   new AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey(),
                   new AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey(),
                   new AzureComputerVisionLegacyCommonAnnotatedSecurityKey(),
                   new AzureContentModeratorLegacyCommonAnnotatedSecurityKey(),
                   new AzureContentSafetyLegacyCommonAnnotatedSecurityKey(),
                   new AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey(),
                   new AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey(),
                   new AzureFaceLegacyCommonAnnotatedSecurityKey(),
                   new AzureFormRecognizerLegacyCommonAnnotatedSecurityKey(),
                   new AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey(),
                   new AzureHealthInsightsLegacyCommonAnnotatedSecurityKey(),
                   new AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey(),
                   new AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey(),
                   new AzureKnowledgeLegacyCommonAnnotatedSecurityKey(),
                   new AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey(),
                   new AzureLuisLegacyCommonAnnotatedSecurityKey(),
                   new AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey(),
                   new AzurePersonalizerLegacyCommonAnnotatedSecurityKey(),
                   new AzureQnAMakerLegacyCommonAnnotatedSecurityKey(),
                   new AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey(),
                   new AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey(),
                   new AzureSpeechServicesLegacyCommonAnnotatedSecurityKey(),
                   new AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey(),
                   new AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey(),
                   new AzureTextTranslationLegacyCommonAnnotatedSecurityKey(),
                   new AzureDummyLegacyCommonAnnotatedSecurityKey(),
                   new AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey(),
                   new AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey(),
                   new AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingSearchLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingSearchv7LegacyCommonAnnotatedSecurityKey(),
                   new AzureBingSpeechLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey(),
                   new AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey());

    public static IReadOnlyList<RegexPattern> DataClassification { get; } =
        CreateList(new IPv4(),
                   new IPv6(),
                   new Float(),
                   new Integer(),
                   new GuidValue());

    public static IReadOnlyList<RegexPattern> HighConfidenceThirdPartySecurityModels { get; } =
        CreateList(new NpmAuthorKey(),
                   new SecretScanningSampleToken());

    public static IReadOnlyList<RegexPattern> PreciselyClassifiedSecurityKeys { get; } =
        CombineLists(HighConfidenceMicrosoftSecurityModels,
                     HighConfidenceThirdPartySecurityModels);

    public static IReadOnlyList<RegexPattern> SecretStoreClassificationDetections { get; } =
        CombineLists(PreciselyClassifiedSecurityKeys,
                     UnclassifiedPotentialSecurityKeys);

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

        // Normalized escaped hyphens.
        alphabet = alphabet.Replace(@"\-", "-");

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

    private static IReadOnlyList<RegexPattern> CreateList(params RegexPattern[] patterns)
    {
        return new ReadOnlyCollection<RegexPattern>(patterns);
    }

    private static IReadOnlyList<RegexPattern> CombineLists(params IReadOnlyList<RegexPattern>[] lists)
    {
        var combined = new List<RegexPattern>(lists.Sum(l => l.Count));
        foreach (IReadOnlyList<RegexPattern> list in lists)
        {
            combined.AddRange(list);
        }
        return combined.AsReadOnly();
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
    private const string SparseUrlSafeBase64 = @$"{SparseBase62}\-"; // Underscore elided.
    private const string SparseUrlUnreserved = $"{SparseUrlSafeBase64}~"; // Period elided.

    public const string Digit = "1234567890";
    public const string Hexadecimal = $"{Digit}abcdef";
    public const string Lowercase = "abcdefghijklmnopqrstuvwxyz";
    public const string Uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    public const string Alpha = $"{Lowercase}{Uppercase}";
    public const string Base62 = $"{Alpha}{Digit}";
    public const string Base64 = $"{Base62}+/";
    public const string UrlSafeBase64 = @$"{Base62}_\-";
    public const string UrlUnreserved = @$"{Base62}_~.\-";

    private const string End = "$";
    private const string Start = "^";

    public const string RegexEncodedUrlSafeBase64 = @$"{Base62}_\-";
    public const string RegexEncodedUrlUnreserved = @$"~.{RegexEncodedUrlSafeBase64}";
    public const string PrefixUrlSafeBase64 = $"({Start}|[^{RegexEncodedUrlSafeBase64}])";
    public const string SuffixUrlSafeBase64 = $"([^{RegexEncodedUrlSafeBase64}]|{End})";

    public const string PrefixUrlUnreserved = $"({Start}|[^{RegexEncodedUrlUnreserved}+/])";
    public const string SuffixUrlUnreserved = $"([^{RegexEncodedUrlUnreserved}+/]|{End})";
    public const string PrefixBase62 = $"({Start}|[^{Base62}])";
    public const string SuffixBase62 = $"([^{Base62}]|{End})";
    public const string PrefixAllBase64 = @$"({Start}|[^{Base64}_\-])";
    public const string SuffixAllBase64 = @$"([^{Base64}_=\-]|{End})";
    public const string PrefixHexadecimal = $"({Start}|[^{Hexadecimal}])";
    public const string SuffixHexadecimal = $"([^{Hexadecimal}]|{End})";

    internal static readonly string[] AllPrefixes = [
        PrefixUrlSafeBase64,
        PrefixUrlUnreserved,
        PrefixBase62,
        PrefixAllBase64,
        PrefixHexadecimal,
    ];

    internal static readonly string[] AllSuffixes = [
        SuffixUrlSafeBase64,
        SuffixUrlUnreserved,
        SuffixBase62,
        SuffixAllBase64,
        SuffixHexadecimal,
    ];
}
