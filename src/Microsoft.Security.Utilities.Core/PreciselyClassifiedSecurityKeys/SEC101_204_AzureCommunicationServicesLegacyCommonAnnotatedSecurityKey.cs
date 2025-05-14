// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;

namespace Microsoft.Security.Utilities;

public class AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey : LegacyCommonAnnotatedSecurityAccessKey
{
    public AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey() : base()
    {
        Id = "SEC101/204";
        Name = nameof(AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey);
        Label = "an Azure Communication Services legacy common annotated security key";
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureCommunicationServices;

    public override Version CreatedVersion => Releases.Version_01_18_00;
}
