// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AadClientAppIdentifiableCredentials : RegexPattern
    {
        public AadClientAppIdentifiableCredentials()
        {
            Id = "SEC101/156";
            Name = "AadClientAppIdentifiableCredentials";
            DetectionMetadata = DetectionMetadata.Identifiable;
            Pattern = $"{WellKnownRegexPatterns.PrefixUrlUnreserved}(?<refine>[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{3}}(7|8)Q~[{WellKnownRegexPatterns.RegexEncodedUrlUnreserved}]{{31,34}}){WellKnownRegexPatterns.SuffixUrlUnreserved}";
            Signatures = new HashSet<string>(new[] { "8Q~", "7Q~" });
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if ((match.Length == 37 && match[3] == '7') || (match.Length == 40 && match[3] == '8'))
            {
                return base.GetMatchIdAndName(match);
            }

            return null;
        }

        public override IEnumerable<string> GenerateTestExamples()
        {
            yield return $"yyy7Q~yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";
            yield return $"zzz8Q~zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzblP";
        }
    }
}