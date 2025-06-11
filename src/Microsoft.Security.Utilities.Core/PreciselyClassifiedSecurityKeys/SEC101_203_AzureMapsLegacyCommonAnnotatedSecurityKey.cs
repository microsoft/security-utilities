// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureMapsLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureMapsLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/203";
        Name = nameof(AzureMapsLegacyCommonAnnotatedSecurityKey);
        Label = Resources.Label_SEC101_203_AzureMapsLegacyCommonAnnotatedSecurityKey;
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureMaps;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
