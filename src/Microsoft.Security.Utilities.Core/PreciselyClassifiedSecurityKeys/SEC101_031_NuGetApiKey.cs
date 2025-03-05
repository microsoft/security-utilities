// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public class NuGetApiKey : RegexPattern
    {
        private const string Base32 = "abcdefghijklmnopqrstuvwxyz234567";

        public NuGetApiKey()
        {
            Id = "SEC101/031";
            Name = nameof(NuGetApiKey);
            DetectionMetadata = DetectionMetadata.FixedSignature | DetectionMetadata.HighEntropy | DetectionMetadata.HighConfidence;

            // This is the ApiKeyV4 format implemented here:
            // https://github.com/NuGet/NuGetGallery/blob/main/src/NuGetGallery.Services/Authentication/ApiKeyV4.cs
            Pattern = "(?i)(^|[^a-z0-9])(?P<refine>oy2[a-z2-7]{43})([^a-z0-9]|$)";

            Signatures = new HashSet<string>(new[] { "oy2", "OY2" });
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (match.Any(char.IsLower) && match.Any(char.IsUpper))
            {
                // The API key is not all uppercase, which is non-standard but accepted by the service.
                // Nullify the match if there is a mix of upper and lowercase to improve redaction.
                // A match with a mix of case is more likely to be base64 than a real API key.
                return null;
            }

            return base.GetMatchIdAndName(match);
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // matches the older, GUID-based entropy source
            yield return $"oy2a{WellKnownRegexPatterns.RandomLowercase(15)}a{WellKnownRegexPatterns.RandomLowercase(11)}e7a{WellKnownRegexPatterns.RandomLowercase(11)}a";

            // matches the newer, PRNG-based entropy source
            yield return $"oy2{WellKnownRegexPatterns.GenerateString(Base32, 43)}";

            // uppercase API key, which is non-standard but accepted by the service
            yield return $"OY2{WellKnownRegexPatterns.GenerateString(Base32, 43).ToUpperInvariant()}";

            // repeat a single base32 character 43 times, for an obviously contrived example
            yield return $"oy2{new string(WellKnownRegexPatterns.GenerateString(Base32, 1)[0], 43)}";
        }

        public override IEnumerable<string> GenerateFalsePositiveExamples()
        {
            // mixed case, excluded by GetMatchIdAndName
            yield return $"oy2{WellKnownRegexPatterns.GenerateString(Base32, 10)}{WellKnownRegexPatterns.GenerateString(Base32, 33).ToUpperInvariant()}";
        }
    }
}