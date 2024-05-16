// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class RegexEngineDetectionBenchmarks
    {
        // The # of iterations of the scan to run.
        private const int s_iterations = 10;

        // The size of randomized data to add as a prefix
        // for every secret. This is intended to make positive
        // hit less concentrated in the profiling.
        private const int secretPrefixSize = 1000 * 1024;

        private static readonly string prefix = GenerateRandomData(secretPrefixSize);

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

        private static IEnumerable<RegexPattern> RegexPatterns()
        {
            foreach (RegexPattern regexPattern in WellKnownRegexPatterns.HighConfidenceSecurityModels)
            {
                if  (regexPattern is Azure32ByteIdentifiableKey ||
                     regexPattern is Azure64ByteIdentifiableKey)
                {
                    yield return regexPattern;
                }

                yield return WellKnownRegexPatterns.AadClientAppIdentifiableCredentialsCurrent();
                yield return WellKnownRegexPatterns.AadClientAppIdentifiableCredentialsPrevious();
            }
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
                        int count = masker.DetectSecrets($"{prefix} {example}").Count();

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
