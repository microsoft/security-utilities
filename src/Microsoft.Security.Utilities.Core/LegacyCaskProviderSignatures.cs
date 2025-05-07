// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;

namespace Microsoft.Security.Utilities;

public static class LegacyCaskProviderSignatures
{
    public static ISet<string> All = new HashSet<string>
    {
        SqlServerPrivate,
        AzureAppConfiguration,
        AzureFluidRelay,
        AzureEventGrid,
        AzureDevOps,
        AzureMixedReality,
        AzureMaps,
    };

    /// <summary>
    /// The private SQL Server legacy CASK provider signature, as used by
    /// 'SEC101/177.SqlPrivateDefaultCloudSALegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string SqlServerPrivate = "msql";

    /// <summary>
    /// The Azure App Configuration legacy CASK provider signature, as used by
    /// 'SEC101/197.AzureAppConfigurationLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureAppConfiguration = "AZAC";

    /// <summary>
    /// The Azure Fluid Relay legacy CASK provider signature, as used by
    /// 'SEC101/198.AzureFluidRelayLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureFluidRelay = "AZFR";

    /// <summary>
    /// The Azure Event Grid legacy CASK provider signature, as used by
    /// 'SEC101/199.AzureEventGridLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureEventGrid = "AZEG";

    /// <summary>
    /// 'SEC101/201.AzureDevOpsLegacyCommonAnnotatedSecurityKeyPat'.
    /// The Azure DevOps legacy CASK provider signature, as used by
    /// </summary>
    public const string AzureDevOps = "AZDO";

    /// <summary>
    /// 'SEC101/202.AzureMixedRealityLegacyCommonAnnotatedSecurityKey'.
    /// The Azure Mixed Reality legacy CASK provider signature, as used by
    /// </summary>
    public const string AzureMixedReality = "AZMR";
    
    /// <summary>
    /// The Azure Maps legacy CASK provider signature, as used by
    /// 'SEC101/203.AzureMapsLegacyCommonAnnotatedSecurityKey'.
    // </summary>
    public const string AzureMaps= "AZMP";
}