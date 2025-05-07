// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/228";
        Name = nameof(AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Speaker Recognition (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureSpeakerRecognition;
}