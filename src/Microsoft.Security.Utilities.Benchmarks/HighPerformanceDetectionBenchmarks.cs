// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class HighPerformanceDetectionBenchmarks : SecretMaskerDetectionBenchmarks
    {
        protected override IEnumerable<RegexPattern> RegexPatterns { get; } = WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys
                                                                                                    .Where(x => x is IHighPerformanceScannableKey)
                                                                                                    .ToList();
    }
}
