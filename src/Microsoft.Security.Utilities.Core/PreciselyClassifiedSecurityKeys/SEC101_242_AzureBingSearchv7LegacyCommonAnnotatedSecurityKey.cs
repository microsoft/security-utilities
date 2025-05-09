// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureBingSearchv7LegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureBingSearchv7LegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureBingSearchv7)
    {
        Id = "SEC101/242";
        Name = nameof(AzureBingSearchv7LegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Bing Search v7 (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}