// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;

#nullable enable

namespace Microsoft.Security.Utilities
{
    public abstract class Azure32ByteIdentifiableKey : IdentifiableKey
    {
        public override string Pattern
        {
            get => @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{33}}{RegexNormalizedSignature}[A-P][{WellKnownRegexPatterns.Base64}]{{5}}=){WellKnownRegexPatterns.SuffixAllBase64}";
            protected set => base.Pattern = value;
        }

#if HIGH_PERFORMANCE_CODEGEN
        private protected override IEnumerable<HighPerformancePattern> HighPerformancePatterns => [
            new(Signature,
                MakeHighPerformancePattern(Pattern, Signature),
                signaturePrefixLength: 33,
                minMatchLength: 44,
                maxMatchLength: 44
         )];
#endif
    }
}