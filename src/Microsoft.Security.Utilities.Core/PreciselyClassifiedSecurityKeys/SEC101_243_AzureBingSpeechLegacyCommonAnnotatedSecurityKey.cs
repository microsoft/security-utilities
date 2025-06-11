// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSpeechLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSpeechLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingSpeech)
    {
        Id = "SEC101/243";
        Name = nameof(AzureBingSpeechLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_243_AzureBingSpeechLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}