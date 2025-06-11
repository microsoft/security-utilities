// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureFluidRelayLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureFluidRelayLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/198";
        Name = nameof(AzureFluidRelayLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_198_AzureFluidRelayCommonAnnotatedSecurityKey;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureFluidRelay;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
