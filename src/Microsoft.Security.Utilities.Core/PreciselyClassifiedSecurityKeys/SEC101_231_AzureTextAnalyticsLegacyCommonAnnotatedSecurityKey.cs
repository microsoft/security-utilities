// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureTextAnalytics)
    {
        Id = "SEC101/231";
        Name = nameof(AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_231_AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}