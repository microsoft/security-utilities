// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureAppConfigurationLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureAppConfigurationLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/197";
        Name = nameof(AzureAppConfigurationLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure App Configuration legacy common annotated security key";
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureAppConfiguration;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
