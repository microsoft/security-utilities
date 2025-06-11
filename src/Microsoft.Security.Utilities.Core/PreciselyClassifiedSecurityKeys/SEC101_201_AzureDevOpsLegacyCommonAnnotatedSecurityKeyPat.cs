// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat() : base()
    {
        Id = "SEC101/201";
        Name = nameof(AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat);
        Label = Resources.Label_SEC101_201_AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureDevOps;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
