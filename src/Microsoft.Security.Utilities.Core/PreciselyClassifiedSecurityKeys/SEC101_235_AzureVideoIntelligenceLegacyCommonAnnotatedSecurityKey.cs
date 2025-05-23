// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureVideoIntelligence)
    {
        Id = "SEC101/235";
        Name = nameof(AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Video Intelligence (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}