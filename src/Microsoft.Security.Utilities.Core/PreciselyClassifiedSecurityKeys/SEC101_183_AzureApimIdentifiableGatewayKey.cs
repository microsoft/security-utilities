// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableGatewayKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableGatewayKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/183";
            Name = nameof(AzureApimIdentifiableGatewayKey);
            Label = Resources.Label_SEC101_183_AzureApimIdentifiableGatewayKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimGatewayChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
