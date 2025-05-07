// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAIServicesLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureAIServicesLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/205";
        Name = nameof(AzureAIServicesLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure AI Services (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureAIServices;
}