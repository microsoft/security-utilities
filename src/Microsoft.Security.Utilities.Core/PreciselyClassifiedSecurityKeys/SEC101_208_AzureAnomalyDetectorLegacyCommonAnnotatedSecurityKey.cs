// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureAnomalyDetector)
    {
        Id = "SEC101/208";
        Name = nameof(AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_208_AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}