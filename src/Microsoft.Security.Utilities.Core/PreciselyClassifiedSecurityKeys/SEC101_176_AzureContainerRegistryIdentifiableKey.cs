// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public class AzureContainerRegistryIdentifiableKey : IdentifiableKey
    {
        public AzureContainerRegistryIdentifiableKey() : base(IdentifiableMetadata.AzureContainerRegistrySignature)
        {
            Id = "SEC101/176";
            Name = nameof(AzureContainerRegistryIdentifiableKey);
            Label = Resources.Label_SEC101_176_AzureContainerRegistryIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureContainerRegistryChecksumSeed };
            Pattern = @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{42}}{Regex.Escape(Signature)}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
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

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
