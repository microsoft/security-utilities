// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

#nullable enable

namespace Microsoft.Security.Utilities
{
    public abstract class Azure64ByteIdentifiableKey : IdentifiableKey
    {
        protected Azure64ByteIdentifiableKey(string signature) : base(signature)
        {
            Pattern = $@"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{76}}{Regex.Escape(signature)}[{WellKnownRegexPatterns.Base64}]{{5}}[AQgw]==){WellKnownRegexPatterns.SuffixAllBase64}";
        }

        public override uint KeyLength => 64;

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