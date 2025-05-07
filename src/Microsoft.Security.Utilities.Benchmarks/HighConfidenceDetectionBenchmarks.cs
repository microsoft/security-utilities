// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class HighConfidenceDetectionBenchmarks : SecretMaskerDetectionBenchmarks
    {
        protected override IEnumerable<RegexPattern> RegexPatterns =>
            WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys;
    }
}
