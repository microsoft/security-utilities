// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureApimIdentifiableDirectManagementKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableDirectManagementKey()
        {
            Id = "SEC101/181";
            Name = nameof(AzureApimIdentifiableDirectManagementKey);
        }

        public override string Signature => IdentifiableMetadata.AzureApimSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureApimDirectManagementChecksumSeed };
    }
}
