// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureServiceBusIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureServiceBusIdentifiableKey() : base(IdentifiableMetadata.AzureServiceBusSignature)
        {
            Id = "SEC101/171";
            Name = nameof(AzureServiceBusIdentifiableKey);
            Label = "an Azure Service Bus access key";
        }
    }
}
