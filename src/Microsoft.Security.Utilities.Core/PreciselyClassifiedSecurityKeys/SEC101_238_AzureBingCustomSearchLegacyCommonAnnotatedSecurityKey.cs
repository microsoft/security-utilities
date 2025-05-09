// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingCustomSearch)
    {
        Id = "SEC101/238";
        Name = nameof(AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Custom Search (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}