// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureMetricsAdvisor)
    {
        Id = "SEC101/224";
        Name = nameof(AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Metrics Advisor (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}