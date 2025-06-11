// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingSpellCheckV7)
    {
        Id = "SEC101/245";
        Name = nameof(AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_245_AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}