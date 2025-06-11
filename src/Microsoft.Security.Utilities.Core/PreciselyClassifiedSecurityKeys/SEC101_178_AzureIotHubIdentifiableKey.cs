// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureIotHubIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotHubIdentifiableKey() : base(IdentifiableMetadata.AzureIotSignature)
        {
            Id = "SEC101/178";
            Name = nameof(AzureIotHubIdentifiableKey);
            Label = Resources.Label_SEC101_178_AzureIotHubIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureIotHubChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
