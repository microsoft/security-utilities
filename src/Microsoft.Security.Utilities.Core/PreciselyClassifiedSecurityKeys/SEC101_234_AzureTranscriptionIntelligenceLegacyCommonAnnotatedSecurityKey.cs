// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureTranscriptionIntelligence)
    {
        Id = "SEC101/234";
        Name = nameof(AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_234_AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}