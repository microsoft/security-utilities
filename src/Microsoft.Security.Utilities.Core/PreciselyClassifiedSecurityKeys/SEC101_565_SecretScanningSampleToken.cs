// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class SecretScanningSampleToken : RegexPattern, IHighPerformanceScannableKey
    {

        public SecretScanningSampleToken()
        {
            Id = "SEC101/565";
            Name = nameof(SecretScanningSampleToken);
            Label = "a non-functional secret scanning sample token";
            DetectionMetadata = DetectionMetadata.FixedSignature | DetectionMetadata.HighEntropy | DetectionMetadata.HighConfidence;
            Pattern = @$"{WellKnownRegexPatterns.PrefixBase62}(?P<refine>secret_scanning_ab85fc6f8d7638cf1c11da812da308d43_[0-9A-Za-z]{{5}}){WellKnownRegexPatterns.SuffixBase62}";
            Signatures = new HashSet<string>(["ab85"]);
        }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => [
            new(signature: "ab85",
                scopedRegex: "^secret_scanning_.{4}fc6f8d7638cf1c11da812da308d43_[0-9A-Za-z]{5}",
                signaturePrefixLength: 16,
                minMatchLength: 55,
                maxMatchLength: 55),
        ];
#endif

        public override Version CreatedVersion => Releases.Version_01_04_11;

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"secret_scanning_ab85fc6f8d7638cf1c11da812da308d43_{WellKnownRegexPatterns.RandomBase62(5)}";
        }
    }
}