// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AadClientAppIdentifiableCredentialsPrevious : RegexPattern
    {
        public AadClientAppIdentifiableCredentialsPrevious()
        {
            Id = "SEC101/156";
            Name = "AadClientAppIdentifiableCredentials";
            DetectionMetadata = DetectionMetadata.HighEntropy;
            Pattern = $"{WellKnownRegexPatterns.PrefixUrlUnreserved}(?<refine>[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{3}}7Q~[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{31}}){WellKnownRegexPatterns.SuffixUrlUnreserved}";
            SniffLiterals = new HashSet<string>(new[] { "7Q~" });
        }

        public override IEnumerable<string> GenerateTestExamples()
        {
            yield return $"yyy7Q~yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
        }
    }
}