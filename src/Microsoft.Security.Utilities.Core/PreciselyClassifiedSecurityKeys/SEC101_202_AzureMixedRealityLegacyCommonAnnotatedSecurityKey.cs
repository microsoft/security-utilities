// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureMixedRealityLegacyCommonAnnotatedSecurityKeyPat : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureMixedRealityLegacyCommonAnnotatedSecurityKeyPat() : base()
    {
        Id = "SEC101/202";
        Name = nameof(AzureMixedRealityLegacyCommonAnnotatedSecurityKeyPat);
        Label = Resources.Label_SEC101_202_AzureMixedRealityLegacyCommonAnnotatedSecurityKey;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureMixedReality;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
