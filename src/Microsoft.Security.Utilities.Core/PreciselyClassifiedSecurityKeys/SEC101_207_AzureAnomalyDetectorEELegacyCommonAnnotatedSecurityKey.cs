// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureAnomalyDetectorEE)
    {
        Id = "SEC101/207";
        Name = nameof(AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_207_AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}