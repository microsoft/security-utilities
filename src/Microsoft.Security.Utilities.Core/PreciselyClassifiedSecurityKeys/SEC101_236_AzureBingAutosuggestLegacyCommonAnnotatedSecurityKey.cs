// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingAutosuggest)
    {
        Id = "SEC101/236";
        Name = nameof(AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_236_AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}