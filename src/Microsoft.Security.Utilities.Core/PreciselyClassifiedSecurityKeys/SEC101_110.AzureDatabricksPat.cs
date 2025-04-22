// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureDatabricksPat : RegexPattern, IHighPerformanceScannableKey
    {
        public AzureDatabricksPat()
        {
            Id = "SEC101/110";
            Name = nameof(AzureDatabricksPat);
            Label = "an Azure Databricks personal access token (PAT)";
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.HighConfidence;
            Pattern = $"(?:^|[^0-9a-f\\-])(?P<refine>dapi[0-9a-f\\-]{{32,34}})(?:[^0-9a-f\\-]|$)";
            Signatures = new HashSet<string>(new[] { "dapi" });
        }

#if HIGH_PERFORMANCE_CODEGEN
        IEnumerable<HighPerformancePattern> IHighPerformanceScannableKey.HighPerformancePatterns => [
            new(signature: "dapi",
                scopedRegex: """^.{4}[0-9a-f\-]{32,34}""",
                signaturePrefixLength: 0,
                minMatchLength: 36,
                maxMatchLength: 38
            )
        ];
#endif

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}";
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}-3";
        }
    }
}