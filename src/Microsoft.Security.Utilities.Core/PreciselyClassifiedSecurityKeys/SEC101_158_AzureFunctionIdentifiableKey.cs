﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;

namespace Microsoft.Security.Utilities
{
    public class AzureFunctionIdentifiableKey : IdentifiableKey
    {
        public AzureFunctionIdentifiableKey()
        {
            Id = "SEC101/158";
            Name = nameof(AzureFunctionIdentifiableKey);
        }

        public override bool EncodeForUrl => true;

        override public ISet<string> Signatures => IdentifiableMetadata.AzureFunctionSignature.ToSet();

        override public IEnumerable<ulong> ChecksumSeeds => new[]
        {
            IdentifiableMetadata.AzureFunctionKeyChecksumSeed,
            IdentifiableMetadata.AzureFunctionMasterKeyChecksumSeed,
            IdentifiableMetadata.AzureFunctionSystemKeyChecksumSeed,
        };

        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixUrlSafeBase64}(?<refine>[{WellKnownRegexPatterns.RegexEncodedUrlSafeBase64}]{{44}}{Signatures!.First()}[{WellKnownRegexPatterns.RegexEncodedUrlSafeBase64}]{{5}}[AQgw]==){WellKnownRegexPatterns.SuffixUrlSafeBase64}";
            protected set => base.Pattern = value;
        }

        override public uint KeyLength => 40;
    }
}
