// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureBatchIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureBatchIdentifiableKey()
        {
            Id = "SEC101/163";
            Name = nameof(AzureBatchIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureBatchSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureBatchChecksumSeed };
    }
}
