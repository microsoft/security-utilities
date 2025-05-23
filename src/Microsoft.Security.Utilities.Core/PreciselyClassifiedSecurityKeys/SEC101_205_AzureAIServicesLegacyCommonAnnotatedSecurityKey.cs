// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAIServicesLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureAIServicesLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureAIServices)
    {
        Id = "SEC101/205";
        Name = nameof(AzureAIServicesLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure AI Services (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}