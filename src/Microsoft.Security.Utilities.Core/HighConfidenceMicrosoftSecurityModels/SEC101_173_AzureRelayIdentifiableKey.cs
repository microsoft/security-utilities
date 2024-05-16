// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    public class AzureRelayIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureRelayIdentifiableKey()
        {
            Id = "SEC101/173";
            Name = nameof(AzureRelayIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureRelaySignature;
    }
}
