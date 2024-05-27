// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public abstract class SecretMaskerDetectionBenchmarks
    {
        // The # of iterations of the scan to run.
        protected virtual int Iterations => 10;

        // The size of randomized data to add as a prefix
        // for every secret. This is intended to make positive
        // hit less concentrated in the profiling.
        protected virtual int SecretPrefixSize => 100 * 1024;

        protected virtual string ScanContentPrefix => GenerateRandomData(SecretPrefixSize);

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
        protected virtual bool GenerateCorrelatingIds => false;

        protected abstract IEnumerable<RegexPattern> RegexPatterns { get; }

        [Benchmark]
        public void UseIdentifiableScan()
        {
            var masker = new IdentifiableScan(RegexPatterns,
                                              GenerateCorrelatingIds);

            ScanTestExamples(masker);
        }


        [Benchmark]
        public void UseCachedDotNet()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          CachedDotNetRegex.Instance);

            ScanTestExamples(masker);
        }

        [Benchmark]
        public void UseRE2()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          RE2RegexEngine.Instance);

            ScanTestExamples(masker);
        }

        protected virtual void ScanTestExamples(ISecretMasker masker)
        {
            int globalCount = 0;

            for (int i = 1; i <= Iterations; i++)
            {
                int localCount = 0;

                foreach (var regexPattern in RegexPatterns)
                {
                    foreach (string example in regexPattern.GenerateTestExamples())
                    {
                        localCount++;

                        // Demonstrate classification/detection only.
                        int count = masker.DetectSecrets($"{ScanContentPrefix} {example}").Count();

                        if (count != 1)
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
