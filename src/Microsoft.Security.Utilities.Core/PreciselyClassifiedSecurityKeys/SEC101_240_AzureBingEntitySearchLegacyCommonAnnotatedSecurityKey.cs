// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingEntitySearch)
    {
        Id = "SEC101/240";
        Name = nameof(AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_240_AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}