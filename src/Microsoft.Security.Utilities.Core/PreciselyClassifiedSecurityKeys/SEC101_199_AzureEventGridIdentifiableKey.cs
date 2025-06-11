// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureEventGridIdentifiableKey : Azure32ByteIdentifiableKey
{
    public AzureEventGridIdentifiableKey() : base(IdentifiableMetadata.AzureEventGridSignature)
    {
        Id = "SEC101/199";
        Name = nameof(AzureEventGridIdentifiableKey);
        Label = Resources.Label_SEC101_199_AzureEventGridIdentifiableKey;
        ChecksumSeeds = [0x53656e6452656376];
    }

    public override Version CreatedVersion => Releases.Version_01_04_20;
}
