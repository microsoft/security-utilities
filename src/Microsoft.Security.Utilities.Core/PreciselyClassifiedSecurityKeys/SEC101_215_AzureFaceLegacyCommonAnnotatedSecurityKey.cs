// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureFaceLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureFaceLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureFace)
    {
        Id = "SEC101/215";
        Name = nameof(AzureFaceLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Face (Cognitive Services) legacy common annotated security key";
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}