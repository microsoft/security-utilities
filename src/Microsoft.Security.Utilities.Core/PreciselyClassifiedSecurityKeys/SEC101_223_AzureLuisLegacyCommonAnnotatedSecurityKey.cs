// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureLuisLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureLuisLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureLuis)
    {
        Id = "SEC101/223";
        Name = nameof(AzureLuisLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Luis (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}