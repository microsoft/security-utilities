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
        Label = "an Azure Event Grid legacy common annotated security key";
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureEventGrid;

    public override Version CreatedVersion => Releases.Unreleased;
}
