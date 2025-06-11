// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureContentSafetyLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureContentSafetyLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureContentSafety)
    {
        Id = "SEC101/212";
        Name = nameof(AzureContentSafetyLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_212_AzureContentSafetyLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}