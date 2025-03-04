// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Microsoft.Security.Utilities;

#nullable enable
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

internal sealed class Azure64ByteIdentifiableKeys : RegexPattern
{
    public Azure64ByteIdentifiableKeys()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?P<refine>[{WellKnownRegexPatterns.Base64}]{{76}}(APIM|ACDb|\+(ABa|AMC|ASt))[{WellKnownRegexPatterns.Base64}]{{5}}[AQgw]==)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        RotationPeriod = TimeSpan.FromDays(365 * 2);

        DetectionMetadata = DetectionMetadata.Identifiable;

        Signatures = new HashSet<string>(new[]
        {
            IdentifiableMetadata.AzureApimSignature,
            IdentifiableMetadata.AzureBatchSignature,
            IdentifiableMetadata.AzureStorageSignature,
            IdentifiableMetadata.AzureCosmosDBSignature,
            IdentifiableMetadata.AzureMLClassicSignature,
        });
    }

    public override Tuple<string, string>? GetMatchIdAndName(string match)
    {
        if (match.Length < 81)
        {
            return null;
        }

        string signature = match.Substring(CommonAnnotatedKey.ProviderFixedSignatureOffset, CommonAnnotatedKey.ProviderFixedSignatureLength);

        return signature switch
        {
            IdentifiableMetadata.AzureApimSignature => GetApimMatchIdAndName(match),
            IdentifiableMetadata.AzureBatchSignature => new Tuple<string, string>("SEC101/163", "AzureBatchIdentifiableKey"),
            IdentifiableMetadata.AzureStorageSignature => new Tuple<string, string>("SEC101/152", "AzureStorageAccountIdentifiableKey"),
            IdentifiableMetadata.AzureCosmosDBSignature => new Tuple<string, string>("SEC101/160", "AzureCosmosDBIdentifiableKey"),
            IdentifiableMetadata.AzureMLClassicSignature => new Tuple<string, string>("SEC101/170", "AzureMLWebServiceClassicIdentifiableKey"),
            _ => null,
        };
    }

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        foreach (string sniffLiteral in Signatures!)
        {
            if (sniffLiteral == "APIM")
            {
                continue;
            }

            using var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[1];
            rng.GetBytes(bytes);
            int index = bytes[0] % TerminalCharactersFor64ByteKey.Length;

            char terminal = TerminalCharactersFor64ByteKey[index];
            yield return $"{WellKnownRegexPatterns.RandomBase64(76)}{sniffLiteral}{WellKnownRegexPatterns.RandomBase64(5)}{terminal}==";
        }

        const string signature = IdentifiableMetadata.AzureApimSignature;

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureApimDirectManagementChecksumSeed,
                                                                   64,
                                                                   signature);

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureApimGatewayChecksumSeed,
                                                                   64,
                                                                   signature);

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureApimRepositoryChecksumSeed,
                                                                   64,
                                                                   signature);

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureApimSubscriptionChecksumSeed,
                                                                   64,
                                                                   signature);
    }

    private static Tuple<string, string>? GetApimMatchIdAndName(string match)
    {
        if (IdentifiableMetadata.IsAzureApimIdentifiableDirectManagementKey(match))
        {
            return new Tuple<string, string>("SEC101/181", "AzureApimIdentifiableDirectManagementKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableSubscriptionKey(match))
        {
            return new Tuple<string, string>("SEC101/182", "AzureApimIdentifiableSubscriptionKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableGatewayKey(match))
        {
            return new Tuple<string, string>("SEC101/183", "AzureApimIdentifiableGatewayKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableRepositoryKey(match))
        {
            return new Tuple<string, string>("SEC101/184", "AzureApimIdentifiableRepositoryKey");
        }

        return null;
    }

    private const string TerminalCharactersFor64ByteKey = "AQgw";
}
