// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/237";
        Name = nameof(AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Autosuggest v7 (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureBingAutosuggestv7;
}