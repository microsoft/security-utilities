// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureMLWebServiceClassicIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureMLWebServiceClassicIdentifiableKey()
        {
            Id = "SEC101/170";
            Name = nameof(AzureMLWebServiceClassicIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureMLSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureMLClassicChecksumSeed };
    }
}
