// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureEventGridIdentifiableKey : Azure32ByteIdentifiableKey
    {
        public AzureEventGridIdentifiableKey() : base(IdentifiableMetadata.AzureEventGridSignature)
        {
            Id = "SEC101/199";
            Name = nameof(AzureEventGridIdentifiableKey);
            Label = "an Azure Event Grid legacy identifiable access key";
            ChecksumSeeds = [0x53656e6452656376];
        }
    }
}
