// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey : CognitiveServiceLegacyCommonAnnotatedSecurityKey
{
    public AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey() : base(AzureCognitiveService.AzureInternalAllInOne)
    {
        Id = "SEC101/220";
        Name = nameof(AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_220_AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey;
    }

    public override Version CreatedVersion => Releases.Version_01_18_00;
}