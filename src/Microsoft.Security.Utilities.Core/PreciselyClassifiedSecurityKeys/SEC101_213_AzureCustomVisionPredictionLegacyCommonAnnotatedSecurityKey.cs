// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureCustomVisionPrediction)
    {
        Id = "SEC101/213";
        Name = nameof(AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_213_AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}