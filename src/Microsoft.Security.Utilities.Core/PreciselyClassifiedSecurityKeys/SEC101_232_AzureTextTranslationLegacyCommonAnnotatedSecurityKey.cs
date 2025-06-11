// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureTextTranslationLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureTextTranslationLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureTextTranslation)
    {
        Id = "SEC101/232";
        Name = nameof(AzureTextTranslationLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_232_AzureTextTranslationLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}