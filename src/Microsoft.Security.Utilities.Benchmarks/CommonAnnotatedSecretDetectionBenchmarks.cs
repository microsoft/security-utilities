// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using BenchmarkDotNet.Attributes;

using System;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public class CommonAnnotatedSecretDetectionBenchmarks : SecretMaskerDetectionBenchmarks
    {
        protected override IEnumerable<RegexPattern> RegexPatterns => new RegexPattern[]
        {
            new UnclassifiedLegacyCommonAnnotatedSecurityKey(),
        };
    }   
}
