// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class HighConfidencePatternsBenchmarks : SecretMaskerDetectionBenchmarks
    {
        protected override IEnumerable<RegexPattern> RegexPatterns => new RegexPattern[]
        {
            new UnclassifiedLegacyCommonAnnotatedSecurityKey(),
            new AadClientAppIdentifiableCredentials(),
            new AzureFunctionIdentifiableKey(),
            new AzureSearchIdentifiableQueryKey(),
            new AzureSearchIdentifiableAdminKey(),
            new AzureRelayIdentifiableKey(),
            new AzureEventHubIdentifiableKey(),
            new AzureServiceBusIdentifiableKey(),
            new AzureIotHubIdentifiableKey(),
            new AzureIotDeviceIdentifiableKey(),
            new AzureIotDeviceProvisioningIdentifiableKey(),
            new AzureStorageAccountIdentifiableKey(),
            new AzureCosmosDBIdentifiableKey(),
            new AzureBatchIdentifiableKey(),
            new AzureMLWebServiceClassicIdentifiableKey(),
            new AzureApimIdentifiableDirectManagementKey(),
            new AzureApimIdentifiableSubscriptionKey(),
            new AzureApimIdentifiableGatewayKey(),
            new AzureApimIdentifiableRepositoryKey(),
            new AzureCacheForRedisIdentifiableKey(),
            new AzureContainerRegistryIdentifiableKey(),
// There are all candidate rules that could be considered for the lower-level library.
// Some are obviously feasible to add, others could entail novel detection techniques
// that may or may not be implemented. Most of the less feasible detections are for
// locating obsoleted key formats.
//            new SecretScanningSampleToken();
//            new NuGetApiKey();
//            new AadClientAppLegacyCredentials32();      // SEC101/101
//            new AadClientAppLegacyCredentials34();      // SEC101/101
//            new AdoPat();                               // SEC101/102
//            new AzureCosmosDBLegacyCredentials();       // SEC101/104
//            new AzureStorageAccountLegacyCredentials(); // SEC101/106
//            new AzureMessageLegacyCredentials();
//            new AzureDatabricksPat();
//            new AzureEventGridIdentifiableKey();
        };
    }
}
