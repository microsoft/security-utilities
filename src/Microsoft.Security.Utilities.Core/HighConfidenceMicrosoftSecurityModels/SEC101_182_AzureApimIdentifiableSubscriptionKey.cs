// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableSubscriptionKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableSubscriptionKey()
        {
            Id = "SEC101/182";
            Name = nameof(AzureApimIdentifiableSubscriptionKey);
        }

        public override ISet<string> Signatures => IdentifiableMetadata.AzureApimSignature.ToSet();

        public override IEnumerable<ulong> ChecksumSeeds => new[] { IdentifiableMetadata.AzureApimSubscriptionChecksumSeed };
    }
}
