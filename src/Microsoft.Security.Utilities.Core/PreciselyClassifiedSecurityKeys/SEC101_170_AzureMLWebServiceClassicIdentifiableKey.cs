// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureMLWebServiceClassicIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureMLWebServiceClassicIdentifiableKey() : base(IdentifiableMetadata.AzureMLClassicSignature)
        {
            Id = "SEC101/170";
            Name = nameof(AzureMLWebServiceClassicIdentifiableKey);
            Label = "an Azure ML web service (classic) access key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureMLClassicChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
