// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal class AzureEventGridIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureEventGridIdentifiableKey()
        {
            Id = "SEC101/190";
            Name = nameof(AzureEventGridIdentifiableKey);
        }

        public override string Signature => "AZEG";

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableSecrets.VersionTwoChecksumSeed };
    }
}
