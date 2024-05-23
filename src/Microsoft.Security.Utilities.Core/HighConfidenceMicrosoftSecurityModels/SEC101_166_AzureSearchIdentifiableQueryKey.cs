// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

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

        override public string Signature => IdentifiableMetadata.AzureSearchSignature;

        override public IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed };

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base62}]{{42}}{Signature}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

        override public uint KeyLength => 39;

        public override IEnumerable<string> GenerateTestExamples()
        {
            foreach (var example in base.GenerateTestExamples())
            {
                if (example.Contains("_") || example.Contains("-")) { continue; }
                yield return example;
            }
        }
    }
}
