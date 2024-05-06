// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;
using Microsoft.Security.Utilities;

namespace Benchmarks
{
    public class RegexEngineDetectionBenchmarks
    {
        [Benchmark]
        public void CachedDotNetRegex()
        {
            ScanTestExamples(null);
        }

        [Benchmark]
        public void RE2()
        {
            ScanTestExamples(RE2RegexEngine.Instance);
        }

        private static void ScanTestExamples(IRegexEngine? regexEngine)
        {
            int globalCount = 0;

            // Setting 'generateCorrelatingIds' to false vs. true may be interesting in profiling.
            var masker = new SecretMasker(WellKnownRegexPatterns.HighConfidenceSecurityModels,
                                           generateCorrelatingIds: true,
                                           regexEngine);

            for (int i = 1; i <= 200; i++)
            {
                int localCount = 0;

                foreach (var regexPattern in masker.RegexPatterns)
                {
                    foreach (string example in regexPattern.GenerateTestExamples())
                    {
                        localCount++;
                        // Demonstrate classification/detection only.
                        int count = masker.DetectSecrets(example).Count();

                        if (count == 0)
                        {
                            throw new InvalidOperationException($"Regex {regexPattern.Name} failed to detect example {example}");
                        }

                        globalCount += count;
                    }
                }
            }
        }
    }
}
