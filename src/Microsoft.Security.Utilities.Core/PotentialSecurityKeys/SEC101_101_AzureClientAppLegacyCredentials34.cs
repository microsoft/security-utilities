// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public class AadClientAppLegacyCredentials34 : RegexPattern
{
    public const string AadClientAppLegacyCredentials = nameof(AadClientAppLegacyCredentials);

    /// <summary>
    /// Detect 34-character Azure Active Directory client application legacy credentials.
    /// The generated key is a 34-character string that contains only URL unreserved characters.
    /// </summary>
    public AadClientAppLegacyCredentials34()
    {
        Id = "SEC101/101";
        Name = AadClientAppLegacyCredentials;
        Label = "an Azure Entra client application legacy format password";
        DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat | DetectionMetadata.LowConfidence;
        Pattern = $"^[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{34}}$";
    }

    public override Tuple<string, string> GetMatchIdAndName(string match)
    {
        if (!HasAtLeastOneSymbol(match))
        {
            return null;
        }

        if (DateTime.TryParse(match, out DateTime result))
        {
            return null;
        }

        return base.GetMatchIdAndName(match);
    }

    public override IEnumerable<string> GenerateTruePositiveExamples()
    {
        while (true)
        {
            string key = WellKnownRegexPatterns.RandomUrlUnreserved(34);
            if (HasAtLeastOneSymbol(key))
            {
                yield return key;
                break;
            }
        }
    }

    public override IEnumerable<string> GenerateFalsePositiveExamples()
    {
        yield return "2024-03-07T02:50:56.464790+00:00";
    }

    internal static bool HasAtLeastOneSymbol(string text)
    {
        foreach (char c in text)
        {

            if (c == '-' || c == '~' || c == '_' || c == '.')
            {
                return true;
            }
        }

        return false;
    }
}
