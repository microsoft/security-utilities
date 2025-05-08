// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureRelayIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureRelayIdentifiableKey() : base(IdentifiableMetadata.AzureRelaySignature)
        {
            Id = "SEC101/173";
            Name = nameof(AzureRelayIdentifiableKey);
            Label = "an Azure Relay access key";
        }

        public override Version CreatedVersion => Releases.Version_01_04_10;
    }
}
