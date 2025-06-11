// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureBatchIdentifiableKey : Azure64ByteIdentifiableKey
    {
        public AzureBatchIdentifiableKey() : base(IdentifiableMetadata.AzureBatchSignature)
        {
            Id = "SEC101/163";
            Name = nameof(AzureBatchIdentifiableKey);
            Label = Resources.Label_SEC101_163_AzureBatchIdentifiableKey;
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureBatchChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
