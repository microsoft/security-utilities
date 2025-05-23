﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableRepositoryKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableRepositoryKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/184";
            Name = nameof(AzureApimIdentifiableRepositoryKey);
            Label = "an Azure API Management repository key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimRepositoryChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
