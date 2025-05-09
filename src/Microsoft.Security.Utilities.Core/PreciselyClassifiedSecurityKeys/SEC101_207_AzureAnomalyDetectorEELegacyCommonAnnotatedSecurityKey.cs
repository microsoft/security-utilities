// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureAnomalyDetectorEE)
    {
        Id = "SEC101/207";
        Name = nameof(AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Anomaly Detector EE (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}