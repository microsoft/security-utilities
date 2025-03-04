// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public class AzureSearchIdentifiableQueryKey : IdentifiableKey
    {
        public AzureSearchIdentifiableQueryKey()
        {
            Id = "SEC101/166";
            Name = nameof(AzureSearchIdentifiableQueryKey);
        }

        public override bool EncodeForUrl => true;

        override public ISet<string> Signatures => IdentifiableMetadata.AzureSearchSignature.ToSet();

        override public IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed };

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base62}]{{42}}{Signatures!.First()}[A-D][{WellKnownRegexPatterns.Base62}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

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
            foreach (var example in base.GenerateTruePositiveExamples())
            {
                if (example.Contains("_") || example.Contains("-")) { continue; }
                yield return example;
            }
        }
    }
}
