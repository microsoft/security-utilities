// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable IDE0073 // A source file contains a header that does not match the required text.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

#pragma warning disable CPR139  // Regular expressions should be reused from static fields of properties
#pragma warning disable IDE1006 // Naming rule violation.
#pragma warning disable R9A015  // Use R9 ArgumentOutOfRangeException helper.
#pragma warning disable R9A044  // Assign array of literal values to static field for improved performance.
#pragma warning disable S109    // Assign this magic number to a variable or constant.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

internal sealed class Azure64ByteIdentifiableKeys : RegexPattern
{
    public Azure64ByteIdentifiableKeys()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownRegexPatterns.Base64}]{{76}}(APIM|ACDb|\+(ABa|AMC|ASt))[{WellKnownRegexPatterns.Base64}]{{5}}[AQgw]==)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        RotationPeriod = TimeSpan.FromDays(365 * 2);

        DetectionMetadata = DetectionMetadata.Identifiable;

        SniffLiterals = new HashSet<string>(new[]
        {
            IdentifiableMetadata.AzureApimSignature,
            IdentifiableMetadata.AzureBatchSignature,
            IdentifiableMetadata.AzureStorageSignature,
            IdentifiableMetadata.AzureCosmosDBSignature,
            IdentifiableMetadata.AzureMLClassicSignature,
        });
    }

    public override (string id, string name)? GetMatchIdAndName(string match)
    {
        if (match.Length < 81)
        {
            return null;
        }

        string signature = match.Substring(76, 4);

        return signature switch
        {
            IdentifiableMetadata.AzureApimSignature => GetApimMatchIdAndName(match),
            IdentifiableMetadata.AzureBatchSignature => ("SEC101/163", "AzureBatchIdentifiableKey"),
            IdentifiableMetadata.AzureStorageSignature => ("SEC101/152", "AzureStorageAccountIdentifiableKey"),
            IdentifiableMetadata.AzureCosmosDBSignature => ("SEC101/160", "AzureCosmosDbIdentifiableKeyResource"),
            IdentifiableMetadata.AzureMLClassicSignature => ("SEC101/170", "AzureMLWebServiceClassicIdentifiableKey"),
            _ => null,
        };
    }

    public override IEnumerable<string> GenerateTestExamples()
    {
        foreach (string sniffLiteral in SniffLiterals)
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

    private static (string id, string name)? GetApimMatchIdAndName(string match)
    {
        if (IdentifiableMetadata.IsAzureApimIdentifiableDirectManagementKey(match))
        {
            return ("SEC101/181", "AzureApimIdentifiableDirectManagementKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableSubscriptionKey(match))
        {
            return ("SEC101/182", "AzureApimIdentifiableSubscriptionKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableGatewayKey(match))
        {
            return ("SEC101/183", "AzureApimIdentifiableGatewayKey");
        }

        if (IdentifiableMetadata.IsAzureApimIdentifiableRepositoryKey(match))
        {
            return ("SEC101/184", "AzureApimIdentifiableRepositoryKey");
        }

        return null;
    }

    private const string TerminalCharactersFor64ByteKey = "AQgw";
}
