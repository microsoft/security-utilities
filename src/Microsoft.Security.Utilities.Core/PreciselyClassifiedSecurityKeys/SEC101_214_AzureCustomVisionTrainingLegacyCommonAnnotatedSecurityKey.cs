// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureCustomVisionTraining)
    {
        Id = "SEC101/214";
        Name = nameof(AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_214_AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}