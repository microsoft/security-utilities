// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;

namespace Microsoft.Security.Utilities
{
    public class NpmAuthorKey : RegexPattern, IHighPerformanceScannableKey
    {
        public NpmAuthorKey()
        {
            Id = "SEC101/050";
            Name = nameof(NpmAuthorKey);
            Label = "an NPM author key";
            DetectionMetadata = DetectionMetadata.FixedSignature | DetectionMetadata.HighEntropy | DetectionMetadata.HighConfidence;
            Pattern = @$"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>npm_[{WellKnownRegexPatterns.Base62}]{{36}}){WellKnownRegexPatterns.SuffixBase62}";
            Signatures = new HashSet<string>(new[] { "npm_" });
        }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => [
            new(signature: "npm_",
                scopedRegex: """^.{4}[a-zA-Z0-9]{36}""",
                signaturePrefixLength: 0,
                minMatchLength: 40,
                maxMatchLength: 40)
        ];
#endif

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"npm_{WellKnownRegexPatterns.RandomBase62(36)}";
        }
    }
}