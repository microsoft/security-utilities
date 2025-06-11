// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureContentModeratorLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureContentModeratorLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureContentModerator)
    {
        Id = "SEC101/211";
        Name = nameof(AzureContentModeratorLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_211_AzureContentModeratorLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}