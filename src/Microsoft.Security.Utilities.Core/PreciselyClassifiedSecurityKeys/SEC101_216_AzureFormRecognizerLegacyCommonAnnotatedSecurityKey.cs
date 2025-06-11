// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureFormRecognizerLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureFormRecognizerLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureFormRecognizer)
    {
        Id = "SEC101/216";
        Name = nameof(AzureFormRecognizerLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_216_AzureFormRecognizerLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}