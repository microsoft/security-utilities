// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureSpeechServicesLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureSpeechServicesLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureSpeechServices)
    {
        Id = "SEC101/229";
        Name = nameof(AzureSpeechServicesLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_229_AzureSpeechServicesLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}