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

#pragma warning disable CA1055  // Change the return type of method from 'string' to 'System.Uri'.
#pragma warning disable CPR139  // Regular expressions should be reused from static fields of properties
#pragma warning disable CS1591  // Missing XML comment for publicly visible type or member.
#pragma warning disable IDE1006 // Naming rule violation.
#pragma warning disable R9A014  // Using R9 ThrowsIfNull.
#pragma warning disable R9A015  // Use R9 ArgumentOutOfRangeException helper.
#pragma warning disable R9A044  // Assign array of literal values to static field for improved performance.
#pragma warning disable R9A049  // Newly added symbol must be marked as experimental.
#pragma warning disable S109    // Assign this magic number to a variable or constant.
#pragma warning disable S1067
#pragma warning disable S3995   // Convert this return type to 'System.Uri'.
#pragma warning disable S125    // Remove uncommented code.
#pragma warning disable S2328
#pragma warning disable SA1204  // Static members should appear before non-static members.
#pragma warning disable SA1600  // Elements should be documented.
#pragma warning disable SA1602  // Enumeration items should be documented.
#pragma warning disable SYSLIB0023  // 'RNGCryptoServiceProvider' is obsolete.

internal sealed class Azure32ByteIdentifiableKeys : RegexPattern
{
    public Azure32ByteIdentifiableKeys()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownRegexPatterns.Base64}]{{33}}(AIoT|\+(ASb|AEh|ARm))[A-P][{WellKnownRegexPatterns.Base64}]{{5}}=)" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        RotationPeriod = TimeSpan.FromDays(365 * 2);

        DetectionMetadata = DetectionMetadata.Identifiable;

        SniffLiterals = new HashSet<string>(new[]
        {
            IdentifiableMetadata.AzureIotSignature,
            IdentifiableMetadata.AzureRelaySignature,
            IdentifiableMetadata.AzureEventHubSignature,
            IdentifiableMetadata.AzureServiceBusSignature,
        });
    }

    public override (string id, string name)? GetMatchIdAndName(string match)
    {
        if (match.Length < 38)
        {
            return null;
        }

        string signature = match.Substring(33, 4);

        return signature switch
        {
            IdentifiableMetadata.AzureIotSignature => GetAIoTMatchIdAndName(match),
            IdentifiableMetadata.AzureRelaySignature => ("SEC101/173", "AzureRelayIdentifiableKey"),
            IdentifiableMetadata.AzureEventHubSignature => ("SEC101/172", "AzureEventHubIdentifiableKey"),
            IdentifiableMetadata.AzureServiceBusSignature => ("SEC101/171", "AzureServiceBusIdentifiableKey"),
            _ => null,
        };
    }

    public override IEnumerable<string> GenerateTestExamples()
    {
        const string aiotSignature = IdentifiableMetadata.AzureIotSignature;

        foreach (string sniffLiteral in SniffLiterals)
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

    private static (string id, string name) GetAIoTMatchIdAndName(string match)
    {
        if (IdentifiableMetadata.IsAzureIotHubIdentifiableKey(match))
        {
            return ("SEC101/178", "AzureIotHubIdentifiableKey");
        }

        if (IdentifiableMetadata.IsAzureIotDeviceProvisioningIdentifiableKey(match))
        {
            return ("SEC101/179", "AzureIotDeviceProvisioningIdentifiableKey");
        }

        if (IdentifiableMetadata.IsAzureIotDeviceIdentifiableKey(match))
        {
            return ("SEC101/180", "AzureIotDeviceIdentifiableKey");
        }

        throw new ArgumentException("Received a match that was not an APIM secret.");
    }

    private const string TerminalCharactersFor32ByteKey = "ABCDEFGHIJKLMNOP";
}
