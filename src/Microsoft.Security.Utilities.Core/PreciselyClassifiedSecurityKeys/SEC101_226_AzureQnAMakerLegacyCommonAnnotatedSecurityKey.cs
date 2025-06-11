// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureQnAMakerLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureQnAMakerLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureQnAMaker)
    {
        Id = "SEC101/226";
        Name = nameof(AzureQnAMakerLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_226_AzureQnAMakerLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}