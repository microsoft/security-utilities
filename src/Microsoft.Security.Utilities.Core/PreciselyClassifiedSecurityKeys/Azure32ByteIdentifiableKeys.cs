// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace Microsoft.Security.Utilities;

#nullable enable

#pragma warning disable SA1600  // Elements should be documented.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

internal sealed class Azure32ByteIdentifiableKeys : RegexPattern
{
    public Azure32ByteIdentifiableKeys()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?P<refine>[{WellKnownRegexPatterns.Base64}]{{33}}(AIoT|\+(ASb|AEh|ARm))[A-P][{WellKnownRegexPatterns.Base64}]{{5}}=)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        RotationPeriod = TimeSpan.FromDays(365 * 2);

        DetectionMetadata = DetectionMetadata.Identifiable;

        Signatures = new HashSet<string>(new[]
        {
            IdentifiableMetadata.AzureIotSignature,
            IdentifiableMetadata.AzureRelaySignature,
            IdentifiableMetadata.AzureEventHubSignature,
            IdentifiableMetadata.AzureServiceBusSignature,
        });
    }

    public override Tuple<string, string>? GetMatchIdAndName(string match)
    {
        if (match.Length < 38)
        {
            return null;
        }

        string signature = match.Substring(33, 4);

        return signature switch
        {
            IdentifiableMetadata.AzureIotSignature => GetAIoTMatchIdAndName(match),
            IdentifiableMetadata.AzureRelaySignature => new Tuple<string, string>("SEC101/173", "AzureRelayIdentifiableKey"),
            IdentifiableMetadata.AzureEventHubSignature => new Tuple<string, string>("SEC101/172", "AzureEventHubIdentifiableKey"),
            IdentifiableMetadata.AzureServiceBusSignature => new Tuple<string, string>("SEC101/171", "AzureServiceBusIdentifiableKey"),
            _ => null,
        };
    }

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        const string aiotSignature = IdentifiableMetadata.AzureIotSignature;

        foreach (string sniffLiteral in Signatures!)
        {
            if (sniffLiteral == aiotSignature)
            {
                continue;
            }

            int index;

            using var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[1];
            rng.GetBytes(bytes);
            index = bytes[0] % 4;

            char terminal = TerminalCharactersFor32ByteKey[index];
            yield return $"{WellKnownRegexPatterns.RandomBase64(33)}{sniffLiteral}{terminal}{WellKnownRegexPatterns.RandomBase64(5)}=";
        }

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureIotHubChecksumSeed,
                                                                   32,
                                                                   aiotSignature);

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureIotDeviceProvisioningChecksumSeed,
                                                                   32,
                                                                   aiotSignature);

        yield return IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureIotDeviceChecksumSeed,
                                                                   32,
                                                                   aiotSignature);
    }

    private static Tuple<string, string> GetAIoTMatchIdAndName(string match)
    {
        if (IdentifiableMetadata.IsAzureIotHubIdentifiableKey(match))
        {
            return new Tuple<string, string>("SEC101/178", "AzureIotHubIdentifiableKey");
        }

        if (IdentifiableMetadata.IsAzureIotDeviceProvisioningIdentifiableKey(match))
        {
            return new Tuple<string, string>("SEC101/179", "AzureIotDeviceProvisioningIdentifiableKey");
        }

        if (IdentifiableMetadata.IsAzureIotDeviceIdentifiableKey(match))
        {
            return new Tuple<string, string>("SEC101/180", "AzureIotDeviceIdentifiableKey");
        }

        throw new ArgumentException("Received a match that was not an APIM secret.");
    }

    private const string TerminalCharactersFor32ByteKey = "ABCDEFGHIJKLMNOP";
}
