// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureIotHubIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureIotHubIdentifiableKey()
        {
            Id = "SEC101/178";
            Name = nameof(AzureIotHubIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureIotSignature;

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureIotHubChecksumSeed };
    }
}
