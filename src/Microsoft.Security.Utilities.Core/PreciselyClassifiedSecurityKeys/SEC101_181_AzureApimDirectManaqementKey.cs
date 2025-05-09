﻿// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities
{
    public class AzureApimIdentifiableDirectManagementKey : Azure64ByteIdentifiableKey
    {
        public AzureApimIdentifiableDirectManagementKey() : base(IdentifiableMetadata.AzureApimSignature)
        {
            Id = "SEC101/181";
            Name = nameof(AzureApimIdentifiableDirectManagementKey);
            Label = "an Azure API Management direct management key";
            ChecksumSeeds = new[] { IdentifiableMetadata.AzureApimDirectManagementChecksumSeed };
        }

        public override Version CreatedVersion => Releases.Version_01_04_02;
    }
}
