// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureContentSafetyLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureContentSafetyLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/212";
        Name = nameof(AzureContentSafetyLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Content Safety (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureContentSafety;
}