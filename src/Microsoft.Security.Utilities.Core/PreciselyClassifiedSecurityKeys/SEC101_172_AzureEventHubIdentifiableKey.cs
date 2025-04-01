// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities
{
    public class AzureEventHubIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureEventHubIdentifiableKey() : base(IdentifiableMetadata.AzureEventHubSignature)
        {
            Id = "SEC101/172";
            Name = nameof(AzureEventHubIdentifiableKey);
            Label = "an Azure Event Hub access key";
            Signatures = IdentifiableMetadata.AzureEventHubSignature.ToSet();
        }
    }
}
