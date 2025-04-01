// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableGatewayKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableGatewayKey()
        {
            Id = "SEC101/183";
            Name = nameof(AzureApimIdentifiableGatewayKey);
            Label = "an Azure API Management gateway key";
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureApimSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureApimGatewayChecksumSeed };
    }
}
