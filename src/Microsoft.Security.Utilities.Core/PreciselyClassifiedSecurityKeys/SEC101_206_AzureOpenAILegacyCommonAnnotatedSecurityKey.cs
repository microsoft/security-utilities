// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureOpenAILegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureOpenAILegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureOpenAI)
    {
        Id = "SEC101/206";
        Name = nameof(AzureOpenAILegacyCommonAnnotatedSecurityKey);
        Label = "an Azure OpenAI (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}