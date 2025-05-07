// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureHealthInsightsLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureHealthInsightsLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/218";
        Name = nameof(AzureHealthInsightsLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Health Insights (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureHealthInsights;
}