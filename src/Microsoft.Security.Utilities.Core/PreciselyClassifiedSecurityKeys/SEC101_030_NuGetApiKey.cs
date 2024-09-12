// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
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
            Pattern = "(^|[^0-9a-z])(?<refine>oy2[a-p][0-9a-z]{15}[aq][0-9a-z]{11}[eu][bdfhjlnprtvxz357][a-p][0-9a-z]{11}[aeimquy4])([^aeimquy4]|$)";
            Signatures = new HashSet<string>(new[] { "oy2" });
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"oy2a{WellKnownRegexPatterns.RandomLowercase(15)}a{WellKnownRegexPatterns.RandomLowercase(11)}e7a{WellKnownRegexPatterns.RandomLowercase(11)}a";
        }
    }
}