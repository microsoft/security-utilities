// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureIotDeviceProvisioningIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotDeviceProvisioningIdentifiableKey()
        {
            Id = "SEC101/179";
            Name = nameof(AzureIotDeviceProvisioningIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureIotSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureIotDeviceProvisioningChecksumSeed };
    }
}
