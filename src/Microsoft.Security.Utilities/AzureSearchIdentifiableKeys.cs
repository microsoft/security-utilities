
// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.


// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

internal sealed class AzureSearchIdentifiableKeys : RegexPattern
{
    public AzureSearchIdentifiableKeys()
    {
        Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}" +
                  $@"(?<refine>[{WellKnownRegexPatterns.Base62}]{{42}}{IdentifiableMetadata.AzureSearchSignature}[A-D][{WellKnownRegexPatterns.Base62}]{{5}})" +
                  $@"{WellKnownRegexPatterns.SuffixAllBase64}";

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
