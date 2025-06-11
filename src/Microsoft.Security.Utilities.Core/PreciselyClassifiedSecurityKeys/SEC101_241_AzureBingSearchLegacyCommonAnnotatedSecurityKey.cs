// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSearchLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSearchLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingSearch)
    {
        Id = "SEC101/241";
        Name = nameof(AzureBingSearchLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_241_AzureBingSearchLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}