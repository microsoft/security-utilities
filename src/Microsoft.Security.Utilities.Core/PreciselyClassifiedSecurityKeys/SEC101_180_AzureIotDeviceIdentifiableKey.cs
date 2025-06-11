// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureIotDeviceIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotDeviceIdentifiableKey() : base(IdentifiableMetadata.AzureIotSignature)
        {
            Id = "SEC101/180";
            Name = nameof(AzureIotDeviceIdentifiableKey);
            Label = Resources.Label_SEC101_180_AzureIotDeviceIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureIotDeviceChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
