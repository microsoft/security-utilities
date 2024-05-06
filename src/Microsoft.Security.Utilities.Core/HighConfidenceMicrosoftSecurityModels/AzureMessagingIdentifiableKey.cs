// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    internal abstract class AzureMessagingIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public override IEnumerable<ulong> ChecksumSeeds => new[]
        {
            IdentifiableMetadata.AzureMessagingSendKeyChecksumSeed,
            IdentifiableMetadata.AzureMessagingListenKeyChecksumSeed,
            IdentifiableMetadata.AzureMessagingManageKeyChecksumSeed,
        };
    }
}
