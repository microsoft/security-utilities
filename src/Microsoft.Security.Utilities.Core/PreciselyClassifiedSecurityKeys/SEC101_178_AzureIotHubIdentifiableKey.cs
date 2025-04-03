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
            Label = "an Azure IoT Hub access key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureIotHubChecksumSeed };
        }
    }
}
