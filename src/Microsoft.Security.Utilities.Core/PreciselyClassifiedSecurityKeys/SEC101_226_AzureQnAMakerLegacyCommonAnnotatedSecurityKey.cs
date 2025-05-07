// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureQnAMakerLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureQnAMakerLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/226";
        Name = nameof(AzureQnAMakerLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure QnA Maker (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureQnAMaker;
}