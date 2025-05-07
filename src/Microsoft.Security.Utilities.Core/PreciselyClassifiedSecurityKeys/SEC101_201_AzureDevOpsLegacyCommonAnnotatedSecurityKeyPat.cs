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
        Label = "an Azure DevOps legacy CASK personal access token (PAT)";
    }

    protected override string ProviderSignature => LegacyCaskProviderSignatures.AzureDevOps;

    public override Version CreatedVersion => Releases.Unreleased;
}
