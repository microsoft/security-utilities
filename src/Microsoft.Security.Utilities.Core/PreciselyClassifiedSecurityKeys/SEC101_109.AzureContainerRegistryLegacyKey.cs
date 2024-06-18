// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureContainerRegistryLegacyKey : RegexPattern
    {
        public AzureContainerRegistryLegacyKey()
        {
            Id = "SEC101/109";
            Name = nameof(AzureContainerRegistryLegacyKey);
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat;
            Pattern = "^(?i)(?<refine>[a-z0-9=+/]{32})$";
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            string alphabet = $"={WellKnownRegexPatterns.Base64}";
            yield return $"{WellKnownRegexPatterns.GenerateString(alphabet, 32)}";
        }
    }
}