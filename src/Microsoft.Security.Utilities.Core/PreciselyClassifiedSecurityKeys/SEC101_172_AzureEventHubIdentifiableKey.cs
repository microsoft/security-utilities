// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureEventHubIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureEventHubIdentifiableKey() : base(IdentifiableMetadata.AzureEventHubSignature)
        {
            Id = "SEC101/172";
            Name = nameof(AzureEventHubIdentifiableKey);
            Label = "an Azure Event Hub access key";
            Signatures = new HashSet<string>([IdentifiableMetadata.AzureEventHubSignature]);
        }

        public override Version CreatedVersion => Releases.Version_01_04_10;
    }
}
