// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureMLWebServiceClassicIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureMLWebServiceClassicIdentifiableKey()
        {
            Id = "SEC101/170";
            Name = nameof(AzureMLWebServiceClassicIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureMLClassicSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureMLClassicChecksumSeed };
    }
}
