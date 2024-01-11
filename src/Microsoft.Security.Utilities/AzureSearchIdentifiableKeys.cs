// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma warning disable IDE0073 // A source file contains a header that does not match the required text.

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

#pragma warning disable CPR139  // Regular expressions should be reused from static fields of properties
#pragma warning disable R9A044  // Assign array of literal values to static field for improved performance.
#pragma warning disable S109    // Assign this magic number to a variable or constant.

internal sealed class AzureSearchIdentifiableKeys : RegexPattern
{
    public AzureSearchIdentifiableKeys()
    {
        Pattern = $@"{WellKnownPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownPatterns.Base62}]{{42}}{IdentifiableMetadata.AzureSearchSignature}[A-D][{WellKnownPatterns.Base62}]{{5}})" +
                  $@"{WellKnownPatterns.SuffixAllBase64}";

        Regex = new Regex(Pattern, DefaultRegexOptions);

        RotationPeriod = TimeSpan.FromDays(365 * 2);

        DetectionMetadata = DetectionMetadata.Identifiable;

        SniffLiterals = new HashSet<string>(new[]
        {
            IdentifiableMetadata.AzureSearchSignature,
        });
    }

    public override (string id, string name)? GetMatchIdAndName(string match)
    {
        if (IdentifiableMetadata.IsAzureSearchIdentifiableQueryKey(match))
        {
            return ("SEC101/166", "AzureSearchIdentifiableQueryKey");
        }

        if (IdentifiableMetadata.IsAzureSearchIdentifiableAdminKey(match))
        {
            return ("SEC101/167", "AzureSearchIdentifiableAdminKey");
        }

        // Received a match that was not an APIM secret.
        return null;
    }

    public override IEnumerable<string> GenerateTestExamples()
    {
        string key;
        while (true)
        {
            key = IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed,
                                                                39,
                                                                IdentifiableMetadata.AzureSearchSignature);
#if NETCOREAPP3_1_OR_GREATER
            if (!key.Contains('+', StringComparison.Ordinal) && !key.Contains('/', StringComparison.Ordinal))
#else
            if (!key.Contains("+") && !key.Contains("/"))
#endif
            {
                yield return key;
                break;
            }
        }

        while (true)
        {
            key = IdentifiableSecrets.GenerateStandardBase64Key(IdentifiableMetadata.AzureSearchAdminKeyChecksumSeed,
                                                                39,
                                                                IdentifiableMetadata.AzureSearchSignature);

#if NETCOREAPP3_1_OR_GREATER
            if (!key.Contains('+', StringComparison.Ordinal) && !key.Contains('/', StringComparison.Ordinal))
#else
            if (!key.Contains("+") && !key.Contains("/"))
#endif
            {
                yield return key;
                break;
            }
        }
    }
}
