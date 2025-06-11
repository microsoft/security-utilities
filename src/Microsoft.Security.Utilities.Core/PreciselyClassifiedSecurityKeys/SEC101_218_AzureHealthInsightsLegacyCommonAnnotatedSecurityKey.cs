// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureHealthInsightsLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureHealthInsightsLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureHealthInsights)
    {
        Id = "SEC101/218";
        Name = nameof(AzureHealthInsightsLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_218_AzureHealthInsightsLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}