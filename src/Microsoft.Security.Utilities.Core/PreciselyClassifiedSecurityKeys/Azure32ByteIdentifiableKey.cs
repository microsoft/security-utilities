// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

#nullable enable

namespace Microsoft.Security.Utilities
{
    public abstract class Azure32ByteIdentifiableKey : IdentifiableKey
    {
        protected Azure32ByteIdentifiableKey(string signature) : base(signature)
        {
            Pattern = @$"{WellKnownRegexPatterns.PrefixAllBase64}(?P<refine>[{WellKnownRegexPatterns.Base64}]{{33}}{Regex.Escape(signature)}[A-P][{WellKnownRegexPatterns.Base64}]{{5}}=){WellKnownRegexPatterns.SuffixAllBase64}";
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