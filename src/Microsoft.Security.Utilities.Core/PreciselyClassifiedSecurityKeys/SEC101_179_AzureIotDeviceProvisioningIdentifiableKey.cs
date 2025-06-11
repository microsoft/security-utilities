// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureIotDeviceProvisioningIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotDeviceProvisioningIdentifiableKey() : base(IdentifiableMetadata.AzureIotSignature)
        {
            Id = "SEC101/179";
            Name = nameof(AzureIotDeviceProvisioningIdentifiableKey);
            Label = Resources.Label_SEC101_179_AzureIotDeviceProvisioningIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureIotDeviceProvisioningChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
