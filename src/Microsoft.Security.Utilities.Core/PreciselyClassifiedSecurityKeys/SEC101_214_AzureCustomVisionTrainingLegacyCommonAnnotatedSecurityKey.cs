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
        Label = "an Azure Custom Vision Training (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}