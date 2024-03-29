﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureCosmosDbIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureCosmosDbIdentifiableKey()
        {
            Id = "SEC101/163";
            Name = nameof(AzureCosmosDbIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureCosmosDBSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] {
            IdentifiableMetadata.AzureCosmosDBDataEncryptionKeyChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBMasterReadOnlyKeyChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBMasterReadWriteKeyChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBResourceKeySeedChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBSystemAllChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBSystemReadOnlyKeyChecksumSeed,
            IdentifiableMetadata.AzureCosmosDBSystemReadWriteKeyChecksumSeed,
        };
    }
}
