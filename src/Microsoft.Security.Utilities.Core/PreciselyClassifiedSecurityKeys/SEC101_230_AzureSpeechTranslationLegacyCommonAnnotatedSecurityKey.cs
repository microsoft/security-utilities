// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureSpeechTranslation)
    {
        Id = "SEC101/230";
        Name = nameof(AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_230_AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}