// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveServices.AzureBingAutosuggest)
    {
        Id = "SEC101/236";
        Name = nameof(AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Autosuggest (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}