// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public class AzureContainerRegistryIdentifiableKey : IdentifiableKey
    {
        public AzureContainerRegistryIdentifiableKey()
        {
            Id = "SEC101/176";
            Name = nameof(AzureContainerRegistryIdentifiableKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureContainerRegistrySignature.ToSet();

        override public IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureContainerRegistryChecksumSeed };

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{42}}{RegexNormalizedSignature}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

        override public uint KeyLength => 39;

#if HIGH_PERFORMANCE_CODEGEN
        private protected override IEnumerable<HighPerformancePattern> HighPerformancePatterns => [
            new(Signature,
                MakeHighPerformancePattern(Pattern, Signature),
                signaturePrefixLength: 42,
                minMatchLength:52,
                maxMatchLength: 52)
        ];
#endif
    }
}
