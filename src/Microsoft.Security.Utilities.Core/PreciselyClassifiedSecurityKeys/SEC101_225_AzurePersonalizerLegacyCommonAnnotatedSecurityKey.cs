// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzurePersonalizerLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzurePersonalizerLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzurePersonalizer)
    {
        Id = "SEC101/225";
        Name = nameof(AzurePersonalizerLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_225_AzurePersonalizerLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}