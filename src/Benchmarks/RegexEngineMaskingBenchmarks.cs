// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

using Microsoft.Security.Utilities;

using System;

namespace Benchmarks
{
    public class RegexEngineMaskingBenchmarks
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
            for (int i = 1; i < 200; i++)
            {
                // Setting 'generateCorrelatingIds' to false vs. true may be interesting in profiling.
                var masker = new SecretMasker(WellKnownRegexPatterns.HighConfidenceSecurityModels,
                                               generateCorrelatingIds: false,
                                               regexEngine);

                foreach (var regexPattern in masker.RegexPatterns)
                {
                    foreach (string example in regexPattern.GenerateTestExamples())
                    {
                        string redacted = masker.MaskSecrets(example);
                        if (redacted == example)
                        {
                            string moniker = $"{regexPattern.Id}.{regexPattern.Name}";
                            throw new InvalidOperationException($"Regex {moniker} failed to redact example {example}");
                        }
                    }
                }
            }
        }
    }
}
