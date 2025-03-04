// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

#nullable enable

namespace Microsoft.Security.Utilities
{
    public abstract class Azure64ByteIdentifiableKey : IdentifiableKey
    {
        public override uint KeyLength => 64;

        public override string Pattern
        {
            get => $@"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{76}}{RegexNormalizedSignature}[{WellKnownRegexPatterns.Base64}]{{5}}[AQgw]==){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

#if HIGH_PERFORMANCE_CODEGEN
        private protected override IEnumerable<HighPerformancePattern> HighPerformancePatterns => [
            new(Signature,
                MakeHighPerformancePattern(Pattern, Signature),
                signaturePrefixLength: 76,
                minMatchLength: 88,
                maxMatchLength: 88)
         ];
#endif
    }
}