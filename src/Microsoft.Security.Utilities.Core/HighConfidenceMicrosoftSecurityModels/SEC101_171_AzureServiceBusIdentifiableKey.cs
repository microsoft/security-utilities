// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    internal class AzureServiceBusIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureServiceBusIdentifiableKey()
        {
            Id = "SEC101/171";
            Name = nameof(AzureServiceBusIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureServiceBusSignature;
    }
}
