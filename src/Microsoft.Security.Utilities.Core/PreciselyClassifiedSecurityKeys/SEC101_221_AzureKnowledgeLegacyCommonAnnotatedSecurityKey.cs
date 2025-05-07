// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureKnowledgeLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureKnowledgeLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/221";
        Name = nameof(AzureKnowledgeLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Knowledge (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureKnowledge;
}