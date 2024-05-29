// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureEventHubIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureEventHubIdentifiableKey()
        {
            Id = "SEC101/172";
            Name = nameof(AzureEventHubIdentifiableKey);
        }

        override public ISet<string> Signatures => IdentifiableMetadata.AzureEventHubSignature.ToSet();
    }
}
