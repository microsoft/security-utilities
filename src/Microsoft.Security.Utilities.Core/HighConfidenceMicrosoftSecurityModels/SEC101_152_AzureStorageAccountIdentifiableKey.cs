﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureStorageAccountIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureStorageAccountIdentifiableKey()
        {
            Id = "SEC101/152";
            Name = nameof(AzureStorageAccountIdentifiableKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureStorageSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureStorageAccountChecksumSeed };
    }
}
