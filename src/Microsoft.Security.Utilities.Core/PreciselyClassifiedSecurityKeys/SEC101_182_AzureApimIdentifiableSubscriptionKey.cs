// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableSubscriptionKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableSubscriptionKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/182";
            Name = nameof(AzureApimIdentifiableSubscriptionKey);
            Label = "an Azure API Management subscription key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimSubscriptionChecksumSeed };
        }
    }
}
