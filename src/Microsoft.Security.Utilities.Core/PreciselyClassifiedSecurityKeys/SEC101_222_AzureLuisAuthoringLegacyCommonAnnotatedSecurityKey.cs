// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/222";
        Name = nameof(AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Luis Authoring (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Unreleased;

    protected override AzureCognitiveServices AzureCognitiveService => AzureCognitiveServices.AzureLuisAuthoring;
}