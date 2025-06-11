// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public class AzureSearchIdentifiableQueryKey : IdentifiableKey
    {
        public AzureSearchIdentifiableQueryKey() : base(IdentifiableMetadata.AzureSearchSignature)
        {
            Id = "SEC101/166";
            Name = nameof(AzureSearchIdentifiableQueryKey);
            Label = Resources.Label_SEC101_166_AzureSearchIdentifiableQueryKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed };
            Pattern = @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base62}]{{42}}{Regex.Escape(Signature)}[A-D][{WellKnownRegexPatterns.Base62}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;

        public override bool EncodeForUrl => true;

        override public uint KeyLength => 39;

#if HIGH_PERFORMANCE_CODEGEN
        private protected override IEnumerable<HighPerformancePattern> HighPerformancePatterns => [
            new(Signature,
                MakeHighPerformancePattern(Pattern, Signature),
                signaturePrefixLength: 42,
                minMatchLength: 52,
                maxMatchLength: 52)
        ];
#endif

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            foreach (string example in base.GenerateTruePositiveExamples())
            {
                if (example.Contains("_") || example.Contains("-")) { continue; }
                yield return example;
            }
        }
    }
}
