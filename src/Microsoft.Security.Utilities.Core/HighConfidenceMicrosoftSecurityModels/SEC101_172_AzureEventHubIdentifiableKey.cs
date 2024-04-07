// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    internal class AzureEventHubIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureEventHubIdentifiableKey()
        {
            Id = "SEC101/172";
            Name = nameof(AzureEventHubIdentifiableKey);
        }

        public override string Signature => IdentifiableMetadata.AzureEventHubSignature;
    }
}
