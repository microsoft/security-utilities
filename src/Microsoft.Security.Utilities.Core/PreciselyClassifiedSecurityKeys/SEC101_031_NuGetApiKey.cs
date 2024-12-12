// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

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
            Pattern = "(^|[^a-zA-Z0-9])(?<refine>oy2[a-z2-7]{43})([^a-zA-Z0-9]|$)";

            Signatures = new HashSet<string>(new[] { "oy2" });
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            // matches the older, GUID-based entropy source
            yield return $"oy2a{WellKnownRegexPatterns.RandomLowercase(15)}a{WellKnownRegexPatterns.RandomLowercase(11)}e7a{WellKnownRegexPatterns.RandomLowercase(11)}a";

            // matches the newer, PRNG-based entropy source
            yield return $"oy2{WellKnownRegexPatterns.GenerateString(Base32, 43)}";

            // repeat a single base32 character 43 times, for an obviously contrived example
            yield return $"oy2{new string(WellKnownRegexPatterns.GenerateString(Base32, 1)[0], 43)}";
        }
    }
}