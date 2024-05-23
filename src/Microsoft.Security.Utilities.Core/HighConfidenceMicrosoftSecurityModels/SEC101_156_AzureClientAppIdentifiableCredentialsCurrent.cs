// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AadClientAppIdentifiableCredentialsCurrent : RegexPattern
    {
        public AadClientAppIdentifiableCredentialsCurrent()
        {
            Id = "SEC101/050";
            Name = "AadClientAppIdentifiableCredentials";
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = $"{WellKnownRegexPatterns.PrefixUrlUnreserved}(?<refine>[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{3}}8Q~[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{34}}){WellKnownRegexPatterns.SuffixUrlUnreserved}";
            SniffLiterals = new HashSet<string>(new[] { "8Q~" });
        }

        public override IEnumerable<string> GenerateTestExamples()
        {
            yield return $"zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzblP";
        }
    }
}