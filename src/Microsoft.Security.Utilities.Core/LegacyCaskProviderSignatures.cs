// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public static class LegacyCaskProviderSignatures
{
    public static ISet<string> All = new HashSet<string>
    {
        AzureDevOps,
        AzureEventGrid,
    };

    /// <summary>
    /// The Azure DevOps legacy CASK provider signature, as used by
    /// 'SEC101/201.AzureEventGridLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureDevOps = "AZDO";

    /// <summary>
    /// The Azure Event Grid legacy CASK provider signature, as used by
    /// 'SEC101/199.AzureEventGridLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureEventGrid = "AZEG";
}
