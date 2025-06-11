// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureStorageAccountLegacyCredentials : RegexPattern
    {
        public AzureStorageAccountLegacyCredentials()
        {
            Id = "SEC101/106";
            Name = nameof(AzureStorageAccountLegacyCredentials);
            Label = Resources.Label_SEC101_106_AzureStorageAccountLegacyCredentials;
            DetectionMetadata = DetectionMetadata.HighEntropy;
            Pattern = "(?i)(?:AccountName|StorageName|StorageAccount)\\s*=.+(?:Account|Storage)Key\\s*=\\s*(?P<refine>[0-9a-z\\\\\\/+]{86}==)(?:[^=]|$)";
        }

        public override Version CreatedVersion => Releases.Version_01_04_10;

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (IdentifiableMetadata.IsAzureStorageAccountIdentifiableKey(match))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }
    }
}
