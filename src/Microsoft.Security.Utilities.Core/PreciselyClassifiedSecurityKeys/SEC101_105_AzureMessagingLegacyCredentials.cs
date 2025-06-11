// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureMessagingLegacyCredentials : RegexPattern
    {
        public AzureMessagingLegacyCredentials()
        {
            Id = "SEC101/105";
            Name = nameof(AzureMessagingLegacyCredentials);
            Label = Resources.Label_SEC101_105_AzureMessagingLegacyCredentials;
            DetectionMetadata = DetectionMetadata.HighEntropy | DetectionMetadata.ObsoleteFormat | DetectionMetadata.MediumConfidence;
            Pattern = "(?i)\\.servicebus\\.windows.+[^0-9a-z\\/+](?P<refine>[0-9a-z\\/+]{43}=)(?:[^=]|$)";
            Signatures = new HashSet<string>(new[] { ".servicebus" });
        }

        public override Version CreatedVersion => Releases.Version_01_04_12;

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (IdentifiableMetadata.IsAzureServiceBusIdentifiableKey(match))
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