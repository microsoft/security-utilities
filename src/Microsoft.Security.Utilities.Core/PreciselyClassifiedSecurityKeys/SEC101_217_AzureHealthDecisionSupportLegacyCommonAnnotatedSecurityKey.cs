// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureHealthDecisionSupport)
    {
        Id = "SEC101/217";
        Name = nameof(AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_217_AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}