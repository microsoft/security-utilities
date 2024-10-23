// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class NuGetApiKey : RegexPattern
    {
        public NuGetApiKey()
        {
            Id = "SEC101/030";
            Name = nameof(NuGetApiKey);
            DetectionMetadata = DetectionMetadata.FixedSignature | DetectionMetadata.HighEntropy| DetectionMetadata.HighConfidence;

            // This is the ApiKeyV4 format implemented here:
            // https://github.com/NuGet/NuGetGallery/blob/main/src/NuGetGallery.Services/Authentication/ApiKeyV4.cs
            Pattern = "(^|[^a-zA-Z0-9])(?<refine>oy2[a-z2-7]{43})([^a-zA-Z0-9]|$)";

            Signatures = new HashSet<string>(new[] { "oy2" });
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"oy2a{WellKnownRegexPatterns.RandomLowercase(15)}a{WellKnownRegexPatterns.RandomLowercase(11)}e7a{WellKnownRegexPatterns.RandomLowercase(11)}a";
        }
    }
}