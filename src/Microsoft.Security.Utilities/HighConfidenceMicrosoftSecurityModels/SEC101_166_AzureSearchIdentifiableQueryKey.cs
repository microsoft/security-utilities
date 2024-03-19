// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureSearchIdentifiableQueryKey : Azure32ByteIdentifiableKey
    {
        public AzureSearchIdentifiableQueryKey()
        {
            Id = "SEC101/166";
            Name = nameof(AzureSearchIdentifiableQueryKey);
        }

        public override string Signature => IdentifiableMetadata.AzureSearchSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureSearchQueryKeyChecksumSeed };
    }
}
