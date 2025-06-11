// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureEventGridLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureEventGridLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/199";
        Name = nameof(AzureEventGridLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_199_AzureEventGridLegacyCommonAnnotatedSecurityKey;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureEventGrid;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
