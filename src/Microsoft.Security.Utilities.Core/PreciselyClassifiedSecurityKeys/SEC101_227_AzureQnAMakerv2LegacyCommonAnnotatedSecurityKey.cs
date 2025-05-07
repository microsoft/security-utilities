// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/227";
        Name = nameof(AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey);
        Label = "an Azure QnA Maker v2 (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureQnAMakerv2;
}