// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureSearchIdentifiableQueryKey : IdentifiableKey
    {
        public AzureSearchIdentifiableQueryKey()
        {
            Id = "SEC101/166";
            Name = nameof(AzureSearchIdentifiableQueryKey);
        }

        override public string Signature => IdentifiableMetadata.AzureSearchSignature;

        override public IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed };

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?<refine>[{WellKnownRegexPatterns.Base64}]{{42}}{Signature}[A-D][{WellKnownRegexPatterns.Base64}]{{5}}){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

        override public uint KeyLength => 39;
    }
}
