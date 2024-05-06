// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureApimIdentifiableRepositoryKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableRepositoryKey()
        {
            Id = "SEC101/184";
            Name = nameof(AzureApimIdentifiableRepositoryKey);
        }

        public override string Signature => IdentifiableMetadata.AzureApimSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureApimRepositoryChecksumSeed };
    }
}
