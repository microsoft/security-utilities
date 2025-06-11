// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureCognitiveServices)
    {
        Id = "SEC101/209";
        Name = nameof(AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_209_AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}