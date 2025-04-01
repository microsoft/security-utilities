// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureBatchIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureBatchIdentifiableKey() : base(IdentifiableMetadata.AzureBatchSignature)
        {
            Id = "SEC101/163";
            Name = nameof(AzureBatchIdentifiableKey);
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureBatchChecksumSeed };
        }
    }
}
