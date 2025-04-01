// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Linq;
using System.Reflection.Emit;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    public class AzureFunctionIdentifiableKey : IdentifiableKey
    {
        public AzureFunctionIdentifiableKey() : base(IdentifiableMetadata.AzureFunctionSignature)
        {
            Id = "SEC101/158";
            Name = nameof(AzureFunctionIdentifiableKey);
            Label = "an Azure Functions access key"; 
            ChecksumSeeds = new[]
            {
                IdentifiableMetadata.AzureFunctionKeyChecksumSeed,
                IdentifiableMetadata.AzureFunctionMasterKeyChecksumSeed,
                IdentifiableMetadata.AzureFunctionSystemKeyChecksumSeed,
            };
            Pattern = @$"{WellKnownRegexPatterns.PrefixUrlSafeBase64}(?P<refine>[{WellKnownRegexPatterns.RegexEncodedUrlSafeBase64}]{{44}}{Regex.Escape(Signature)}[{WellKnownRegexPatterns.RegexEncodedUrlSafeBase64}]{{5}}[AQgw]==){WellKnownRegexPatterns.SuffixUrlSafeBase64}";
        }

        public override bool EncodeForUrl => true;

        override public uint KeyLength => 40;

#if HIGH_PERFORMANCE_CODEGEN
        private protected override IEnumerable<HighPerformancePattern> HighPerformancePatterns => [
            new(Signature,
                MakeHighPerformancePattern(Pattern, Signature),
                signaturePrefixLength: 44,
                minMatchLength: 56,
                maxMatchLength: 56
        )];
#endif
    }
}
