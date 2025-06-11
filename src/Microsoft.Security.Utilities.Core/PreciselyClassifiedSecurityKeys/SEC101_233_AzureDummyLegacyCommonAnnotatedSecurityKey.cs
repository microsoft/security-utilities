// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureDummyLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureDummyLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureDummy)
    {
        Id = "SEC101/233";
        Name = nameof(AzureDummyLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_233_AzureDummyLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}