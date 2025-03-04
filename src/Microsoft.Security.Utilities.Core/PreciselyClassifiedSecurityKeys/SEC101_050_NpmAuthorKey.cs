// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class NpmAuthorKey : RegexPattern
    {
        public NpmAuthorKey()
        {
            Id = "SEC101/050";
            Name = nameof(NpmAuthorKey);
            DetectionMetadata = DetectionMetadata.FixedSignature | DetectionMetadata.HighEntropy | DetectionMetadata.HighConfidence;
            Pattern = @$"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>npm_[{WellKnownRegexPatterns.Base62}]{{36}}){WellKnownRegexPatterns.SuffixBase62}";
            Signatures = new HashSet<string>(new[] { "npm_" });
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"npm_{WellKnownRegexPatterns.RandomBase62(36)}";
        }
    }
}