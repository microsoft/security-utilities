// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class RegexEngineDetectionBenchmarks
    {
        // The # of iterations of the scan to run.
        protected const int s_iterations = 100;

        // The size of randomized data to add as a prefix
        // for every secret. This is intended to make positive
        // hit less concentrated in the profiling.
        private const int secretPrefixSize = 100 * 1024;

        public static readonly string ScanContentPrefix = GenerateRandomData(secretPrefixSize);

        private static string GenerateRandomData(int size)
        {
            var random = new Random();
            var data = new byte[size];
            random.NextBytes(data);
            return Convert.ToBase64String(data);
        }
        
        // Whether to generate correlating ids for each match.
        // Setting this to true will contribute fixed hash
        // production overhead to all the scanners.
        private const bool s_generateCorrelatingIds = false;

        public static IEnumerable<RegexPattern> RegexPatterns()
        {
            yield return new AadClientAppIdentifiableCredentialsCurrent();
            yield return new AadClientAppIdentifiableCredentialsPrevious();
            yield return new AzureFunctionIdentifiableKey();
            yield return new AzureSearchIdentifiableQueryKey();
            yield return new AzureSearchIdentifiableAdminKey();
            yield return new AzureRelayIdentifiableKey();
            yield return new AzureEventHubIdentifiableKey();
            yield return new AzureServiceBusIdentifiableKey();
            yield return new AzureIotHubIdentifiableKey();
            yield return new AzureIotDeviceIdentifiableKey();
            yield return new AzureIotDeviceProvisioningIdentifiableKey();
            yield return new AzureStorageAccountIdentifiableKey();
            yield return new AzureCosmosDBIdentifiableKey();
            yield return new AzureBatchIdentifiableKey();
            yield return new AzureMLWebServiceClassicIdentifiableKey();
            yield return new AzureApimIdentifiableDirectManagementKey();
            yield return new AzureApimIdentifiableSubscriptionKey();
            yield return new AzureApimIdentifiableGatewayKey();
            yield return new AzureApimIdentifiableRepositoryKey();
            yield return new AzureCacheForRedisIdentifiableKey();
            yield return new AzureContainerRegistryIdentifiableKey();
// There are all candidate rules that could be considered for the lower-level library.
// Some are obviously feasible to add, others could entail novel detection techniques
// that may or may not be implemented. Most of the less feasible detections are for
// locating obsoleted key formats.
//            yield return new SecretScanningSampleToken();
//            yield return WellKnownRegexPatterns.NuGetApiKey();
//            yield return new AadClientAppLegacyCredentials32();      // SEC101/101
//            yield return new AadClientAppLegacyCredentials34();      // SEC101/101
//            yield return new AdoPat();                               // SEC101/102
//            yield return new AzureCosmosDBLegacyCredentials();       // SEC101/104
//            yield return new AzureStorageAccountLegacyCredentials(); // SEC101/106
//            yield return new AzureMessageLegacyCredentials();
//            yield return new AzureDatabricksPat();
//            yield return new AzureEventGridIdentifiableKey();
        }

        [Benchmark]
        public void UseIdentifiableScan()
        {
            var masker = new IdentifiableScan(RegexPatterns(),
                                              s_generateCorrelatingIds);

            ScanTestExamples(masker);
        }


        [Benchmark]
        public void UseCachedDotNet()
        {
            var masker = new SecretMasker(RegexPatterns(),
                                          s_generateCorrelatingIds,
                                          CachedDotNetRegex.Instance);

            ScanTestExamples(masker);
        }

        [Benchmark]
        public void UseRE2()
        {
            var masker = new SecretMasker(RegexPatterns(),
                                          s_generateCorrelatingIds,
                                          RE2RegexEngine.Instance);

            ScanTestExamples(masker);
        }

        private static void ScanTestExamples(ISecretMasker masker)
        {
            int globalCount = 0;

            for (int i = 1; i <= s_iterations; i++)
            {
                int localCount = 0;

                foreach (var regexPattern in RegexPatterns())
                {
                    foreach (string example in regexPattern.GenerateTestExamples())
                    {
                        localCount++;

                        // Demonstrate classification/detection only.
                        int count = masker.DetectSecrets($"{ScanContentPrefix} {example}").Count();

                        if (count == 0)
                        {
                            throw new InvalidOperationException($"Regex {regexPattern.Name} failed to detect example {example}");
                        }

                        globalCount += count;
                    }
                }
            }
            Console.WriteLine($"Total matches: {globalCount}");
        }
    }
}
