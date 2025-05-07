// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureTextTranslationLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureTextTranslationLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/232";
        Name = nameof(AzureTextTranslationLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Text Translation (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureTextTranslation;
}