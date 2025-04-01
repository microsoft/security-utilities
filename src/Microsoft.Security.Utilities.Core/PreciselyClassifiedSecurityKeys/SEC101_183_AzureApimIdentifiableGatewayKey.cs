// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableGatewayKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableGatewayKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/183";
            Name = nameof(AzureApimIdentifiableGatewayKey);
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimGatewayChecksumSeed };
        }
    }
}
