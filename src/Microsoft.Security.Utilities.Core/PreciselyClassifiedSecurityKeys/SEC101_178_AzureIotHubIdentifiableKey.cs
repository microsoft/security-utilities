// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureIotHubIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotHubIdentifiableKey()
        {
            Id = "SEC101/178";
            Name = nameof(AzureIotHubIdentifiableKey);
            Label = "an Azure IoT Hub access key";
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureIotSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureIotHubChecksumSeed };
    }
}
