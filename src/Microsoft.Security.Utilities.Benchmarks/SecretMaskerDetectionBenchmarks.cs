// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public abstract class SecretMaskerDetectionBenchmarks
    {
        // The size of randomized data to add as a prefix
        // for every secret. This is intended to make positive
        // hit less concentrated in the profiling.
        private const int SecretPrefixSize = 100 * 1024;

        private readonly List<string> _randomExamples;
        private readonly List<string> _nonRandomExamples;

        // Use a fixed seed to ensure different runs use the same data.
        private readonly Random rng = new Random(Seed: 42);

        protected SecretMaskerDetectionBenchmarks()
        {
            _randomExamples = GenerateExamples(random: true);
            _nonRandomExamples = GenerateExamples(random: false);
        }

        private string GeneratePrefix(int size, bool random)
        {
            string prefix;

            if (random)
            {
                // This is close to the worst case scenario. Every base64
                // alphabet char is equally likely to appear in the input,
                // making signature sniffing harder.
                var data = new byte[size / 4 * 3]; // Account for base64 encoding overhead.
                rng.NextBytes(data);
                prefix = Convert.ToBase64String(data);
            }
            else
            {
                // This is close to the best case scenario. This char does not appear in
                // any identifiable key signature, making signature sniffing easier.
                prefix = new string('%', size);
            }

            if (prefix.Length != size)
            {
                throw new InvalidOperationException("Something is wrong in math above.");
            }

            return prefix;
        }

        private List<string> GenerateExamples(bool random)
        {
            var examples = new List<string>();
            var prefix = GeneratePrefix(SecretPrefixSize, random);

            foreach (var pattern in RegexPatterns)
            {
                foreach (var example in pattern.GenerateTruePositiveExamples())
                {
                    examples.Add($"{prefix} {example}");
                }
            }

            return examples;
        }

        // Whether to generate correlating ids for each match.
        // Setting this to true will contribute fixed hash
        // production overhead to all the scanners.
        protected virtual bool GenerateCorrelatingIds => false;

        protected abstract IEnumerable<RegexPattern> RegexPatterns { get; }

        [Benchmark]
        public void IdentifiableScan_RandomPrefix()
        {
            var masker = new IdentifiableScan(RegexPatterns,
                                              GenerateCorrelatingIds);

            ScanTestExamples(masker, _randomExamples);
        }

        [Benchmark]
        public void IdentifiableScan_NonRandomPrefix()
        {
            var masker = new IdentifiableScan(RegexPatterns,
                                              GenerateCorrelatingIds);

            ScanTestExamples(masker, _nonRandomExamples);
        }

        [Benchmark]
        public void SecretMasker_CachedDotNet_RandomPrefix()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          CachedDotNetRegex.Instance);

            ScanTestExamples(masker, _randomExamples);
        }

        [Benchmark]
        public void SecretMasker_CachedDotNet_NonRandomPrefix()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          CachedDotNetRegex.Instance);

            ScanTestExamples(masker, _nonRandomExamples);
        }

        [Benchmark]
        public void SecretMasker_RE2_RandomPrefix()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          RE2RegexEngine.Instance);

            ScanTestExamples(masker, _randomExamples);
        }

        [Benchmark]
        public void SecretMasker_RE2_NonRandomPrefix()
        {
            var masker = new SecretMasker(RegexPatterns,
                                          GenerateCorrelatingIds,
                                          RE2RegexEngine.Instance);

            ScanTestExamples(masker, _nonRandomExamples);
        }

        private void ScanTestExamples(ISecretMasker masker, List<string> examples)
        {
            foreach (string example in examples)
            {
                int count = masker.DetectSecrets(example).Count();
                if (count != 1)
                {
                    throw new InvalidOperationException("Failed to  detect example.");
                }
            }
        }
    }
}
