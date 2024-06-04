﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureRelayIdentifiableKey : AzureMessagingIdentifiableKey
    {
        public AzureRelayIdentifiableKey()
        {
            Id = "SEC101/173";
            Name = nameof(AzureRelayIdentifiableKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureRelaySignature.ToSet();
    }
}
