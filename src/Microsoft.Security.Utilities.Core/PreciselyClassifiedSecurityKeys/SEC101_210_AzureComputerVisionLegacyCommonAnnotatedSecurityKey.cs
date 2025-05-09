// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureComputerVisionLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureComputerVisionLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureComputerVision)
    {
        Id = "SEC101/210";
        Name = nameof(AzureComputerVisionLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Computer Vision (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}