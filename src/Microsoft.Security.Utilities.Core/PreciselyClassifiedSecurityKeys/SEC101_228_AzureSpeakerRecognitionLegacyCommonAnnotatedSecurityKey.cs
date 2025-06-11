// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureSpeakerRecognition)
    {
        Id = "SEC101/228";
        Name = nameof(AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_228_AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}