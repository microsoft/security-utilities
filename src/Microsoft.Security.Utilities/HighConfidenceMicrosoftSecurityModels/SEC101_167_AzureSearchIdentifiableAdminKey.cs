// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureSearchIdentifiableAdminKey : Azure32ByteIdentifiableKey
    {
        public AzureSearchIdentifiableAdminKey()
        {
            Id = "SEC101/167";
            Name = nameof(AzureSearchIdentifiableAdminKey);
        }

        public override string Signature => IdentifiableMetadata.AzureSearchSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureSearchAdminKeyChecksumSeed };
    }
}
