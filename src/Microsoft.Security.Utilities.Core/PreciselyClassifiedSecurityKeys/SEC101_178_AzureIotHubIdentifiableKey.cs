// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    public class AzureIotHubIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotHubIdentifiableKey() : base(IdentifiableMetadata.AzureIotSignature)
        {
            Id = "SEC101/178";
            Name = nameof(AzureIotHubIdentifiableKey);
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureIotHubChecksumSeed };
        }
    }
}
