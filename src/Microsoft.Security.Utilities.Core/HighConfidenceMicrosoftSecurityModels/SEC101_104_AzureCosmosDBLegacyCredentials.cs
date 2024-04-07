// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net.Sockets;

namespace Microsoft.Security.Utilities
{
    internal class AzureCosmosDBLegacyCredentials : RegexPattern
    {
        public AzureCosmosDBLegacyCredentials()
        {
            Id = "SEC101/104";
            Name = nameof(AzureCosmosDBLegacyCredentials);
            DetectionMetadata = DetectionMetadata.HighEntropy;
            Pattern = "(?i)\\.documents\\.azure\\.com.+(?:^|[^0-9a-z\\/+])(?P<refine>[0-9a-z\\/+]{86}==)(?:[^=]|$)";
        }

        public override Tuple<string, string> GetMatchIdAndName(string match)
        {
            if (IdentifiableMetadata.IsAzureCosmosDBIdentifiableKey(match))
            {
                return null;
            }

            return base.GetMatchIdAndName(match);
        }
    }
}