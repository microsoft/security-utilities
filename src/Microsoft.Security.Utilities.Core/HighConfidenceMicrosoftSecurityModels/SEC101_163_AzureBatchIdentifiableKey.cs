﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureBatchIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureBatchIdentifiableKey()
        {
            Id = "SEC101/163";
            Name = nameof(AzureBatchIdentifiableKey);
        }

        public override ISet<string> Signatures=> IdentifiableMetadata.AzureBatchSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureBatchChecksumSeed };
    }
}
