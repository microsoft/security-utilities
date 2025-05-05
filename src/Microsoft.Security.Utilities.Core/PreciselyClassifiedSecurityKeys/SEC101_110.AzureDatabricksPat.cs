// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureDatabricksPat : RegexPattern
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

        public override Version CreatedVersion => Releases.Version_01_04_12;

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}";
            yield return $"dapi{WellKnownRegexPatterns.RandomHexadecimal(32)}-3";
        }
    }
}