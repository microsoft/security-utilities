// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureStorageAccountIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureStorageAccountIdentifiableKey()
        {
            Id = "SEC101/152";
            Name = nameof(AzureStorageAccountIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureStorageSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureStorageAccountChecksumSeed };
    }
}
