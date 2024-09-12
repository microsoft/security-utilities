// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureMessageLegacyCredentials : RegexPattern
    {
        public AzureMessageLegacyCredentials()
        {
            Id = "SEC101/105";
            Name = nameof(AzureMessageLegacyCredentials);         
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat | DetectionMetadata.MediumConfidence;
            Pattern = "(?i)\\.servicebus\\.windows.+[^0-9a-z\\/+](?P<refine>[0-9a-z\\/+]{43}=)(?:[^=]|$)";
            Signatures = new HashSet<string>(new[] { ".servicebus" });
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (IdentifiableMetadata.IsAzureCosmosDBIdentifiableKey(match))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }

        public override IEnumerable<string> GenerateTruePositiveExamples()
        {
            yield return $"Endpoint=sb://doesnotexist.servicebus.windows.net/;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey={WellKnownRegexPatterns.RandomBase64(43)}=";
        }
    }
}