// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureLuisAuthoring)
    {
        Id = "SEC101/222";
        Name = nameof(AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_222_AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}