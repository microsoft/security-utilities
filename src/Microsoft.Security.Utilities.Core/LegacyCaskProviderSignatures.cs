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
        AzureCommunicationServices,
        AzureCognitiveServices,
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
    /// </summary>
    public const string AzureMaps = "AZMP";

    /// <summary>
    /// The Azure Communication Services legacy CASK provider signature, as used by
    /// 'SEC101/204.AzureCommunicationServicesLegacyCommonAnnotatedSecurityKey'.
    /// </summary>
    public const string AzureCommunicationServices = "AZCS";

    /// <summary>
    /// The Azure Cognitice Services legacy CASK provider signature, as used by
    /// 'SEC101/205.AzureAIServicesLegacyCommonAnnotatedSecurityKey' (among many
    /// other cognitive service providers).
    /// </summary>
    /// <remarks>
    /// Rules that incorporate the general Cognitive Services provider signature
    /// include SEC101/205.AzureAIServicesLegacyCommonAnnotatedSecurityKey,
    /// SEC101/206.AzureOpenAILegacyCommonAnnotatedSecurityKey,
    /// SEC101/207.AzureAnomalyDetectorEELegacyCommonAnnotatedSecurityKey,
    /// SEC101/208.AzureAnomalyDetectorLegacyCommonAnnotatedSecurityKey,
    /// SEC101/209.AzureCognitiveServicesLegacyCommonAnnotatedSecurityKey,
    /// SEC101/210.AzureComputerVisionLegacyCommonAnnotatedSecurityKey,
    /// SEC101/211.AzureContentModeratorLegacyCommonAnnotatedSecurityKey,
    /// SEC101/212.AzureContentSafetyLegacyCommonAnnotatedSecurityKey,
    /// SEC101/213.AzureCustomVisionPredictionLegacyCommonAnnotatedSecurityKey,
    /// SEC101/214.AzureCustomVisionTrainingLegacyCommonAnnotatedSecurityKey,
    /// SEC101/215.AzureFaceLegacyCommonAnnotatedSecurityKey,
    /// SEC101/216.AzureFormRecognizerLegacyCommonAnnotatedSecurityKey,
    /// SEC101/217.AzureHealthDecisionSupportLegacyCommonAnnotatedSecurityKey,
    /// SEC101/218.AzureHealthInsightsLegacyCommonAnnotatedSecurityKey,
    /// SEC101/219.AzureImmersiveReaderLegacyCommonAnnotatedSecurityKey,
    /// SEC101/220.AzureInternalAllInOneLegacyCommonAnnotatedSecurityKey,
    /// SEC101/221.AzureKnowledgeLegacyCommonAnnotatedSecurityKey,
    /// SEC101/222.AzureLuisAuthoringLegacyCommonAnnotatedSecurityKey,
    /// SEC101/223.AzureLuisLegacyCommonAnnotatedSecurityKey,
    /// SEC101/224.AzureMetricsAdvisorLegacyCommonAnnotatedSecurityKey,
    /// SEC101/225.AzurePersonalizerLegacyCommonAnnotatedSecurityKey,
    /// SEC101/226.AzureQnAMakerLegacyCommonAnnotatedSecurityKey,
    /// SEC101/227.AzureQnAMakerv2LegacyCommonAnnotatedSecurityKey,
    /// SEC101/228.AzureSpeakerRecognitionLegacyCommonAnnotatedSecurityKey,
    /// SEC101/229.AzureSpeechServicesLegacyCommonAnnotatedSecurityKey,
    /// SEC101/230.AzureSpeechTranslationLegacyCommonAnnotatedSecurityKey,
    /// SEC101/231.AzureTextAnalyticsLegacyCommonAnnotatedSecurityKey,
    /// SEC101/232.AzureTextTranslationLegacyCommonAnnotatedSecurityKey,
    /// SEC101/233.AzureDummyLegacyCommonAnnotatedSecurityKey,
    /// SEC101/234.AzureTranscriptionIntelligenceLegacyCommonAnnotatedSecurityKey,
    /// SEC101/235.AzureVideoIntelligenceLegacyCommonAnnotatedSecurityKey,
    /// SEC101/236.AzureBingAutosuggestLegacyCommonAnnotatedSecurityKey,
    /// SEC101/237.AzureBingAutosuggestv7LegacyCommonAnnotatedSecurityKey,
    /// SEC101/238.AzureBingCustomSearchLegacyCommonAnnotatedSecurityKey,
    /// SEC101/239.AzureBingCustomVisualSearchLegacyCommonAnnotatedSecurityKey,
    /// SEC101/240.AzureBingEntitySearchLegacyCommonAnnotatedSecurityKey,
    /// SEC101/241.AzureBingSearchLegacyCommonAnnotatedSecurityKey,
    /// SEC101/242.AzureBingSearchv7LegacyCommonAnnotatedSecurityKey,
    /// SEC101/243.AzureBingSpeechLegacyCommonAnnotatedSecurityKey,
    /// SEC101/244.AzureBingSpellCheckLegacyCommonAnnotatedSecurityKey, and
    /// SEC101/245.AzureBingSpellCheckv7LegacyCommonAnnotatedSecurityKey.  
    /// </remarks>
    public const string AzureCognitiveServices = "ACOG";
}