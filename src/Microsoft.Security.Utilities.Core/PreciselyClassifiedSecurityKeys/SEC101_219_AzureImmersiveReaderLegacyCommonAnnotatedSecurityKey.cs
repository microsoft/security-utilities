// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureImmersiveReader)
    {
        Id = "SEC101/219";
        Name = nameof(AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_219_AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}