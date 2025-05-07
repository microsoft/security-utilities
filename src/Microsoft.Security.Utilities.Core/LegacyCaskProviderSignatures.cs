// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public static class LegacyCaskProviderSignatures
{
    public static ISet<string> All = new HashSet<string>
    {
        AzureAppConfiguration,
        AzureEventGrid,
        AzureDevOps,
    };

    /// <summary>
    /// The Azure App COnfiguration legacy CASK provider signature, as used by
    /// 'SEC101/197.AzureAppConfigurationCredentialsLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureAppConfiguration = "AZAC";

    /// <summary>
    /// The Azure Event Grid legacy CASK provider signature, as used by
    /// 'SEC101/199.AzureEventGridLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureEventGrid = "AZEG";

    /// <summary>
    /// The Azure DevOps legacy CASK provider signature, as used by
    /// 'SEC101/201.AzureEventGridLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureDevOps = "AZDO";
}
