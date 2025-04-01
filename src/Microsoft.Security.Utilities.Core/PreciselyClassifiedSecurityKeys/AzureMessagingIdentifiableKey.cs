// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    public abstract class AzureMessagingIdentifiableKey : Azure32ByteIdentifiableKey
    {
        protected AzureMessagingIdentifiableKey(string signature) : base(signature)
        {
            ChecksumSeeds = new[]
            {
                IdentifiableMetadata.AzureMessagingSendKeyChecksumSeed,
                IdentifiableMetadata.AzureMessagingListenKeyChecksumSeed,
                IdentifiableMetadata.AzureMessagingManageKeyChecksumSeed,
            };
        }
    }
}
