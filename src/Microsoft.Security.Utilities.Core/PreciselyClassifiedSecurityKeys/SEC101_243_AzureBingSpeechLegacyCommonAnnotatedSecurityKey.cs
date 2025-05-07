// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSpeechLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSpeechLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/243";
        Name = nameof(AzureBingSpeechLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Speech (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureBingSpeech;
}