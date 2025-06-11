// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureVideoIntelligence)
    {
        Id = "SEC101/235";
        Name = nameof(AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_235_AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}