// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingCustomVisualSearch)
    {
        Id = "SEC101/239";
        Name = nameof(AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Custom VisualSearch (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}