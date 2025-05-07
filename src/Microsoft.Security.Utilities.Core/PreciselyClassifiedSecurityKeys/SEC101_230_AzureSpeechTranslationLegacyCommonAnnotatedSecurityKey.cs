// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/230";
        Name = nameof(AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Speech Translation (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureSpeechTranslation;
}