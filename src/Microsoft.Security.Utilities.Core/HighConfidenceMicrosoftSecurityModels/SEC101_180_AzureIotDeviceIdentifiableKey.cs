// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureIotDeviceIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotDeviceIdentifiableKey()
        {
            Id = "SEC101/180";
            Name = nameof(AzureIotDeviceIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureIotSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureIotDeviceChecksumSeed };
    }
}
