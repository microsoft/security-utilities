// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableDirectManagementKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableDirectManagementKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/181";
            Name = nameof(AzureApimIdentifiableDirectManagementKey);
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimDirectManagementChecksumSeed };
        }
    }
}
