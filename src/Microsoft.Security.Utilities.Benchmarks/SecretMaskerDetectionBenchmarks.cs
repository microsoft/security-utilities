// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using BenchmarkDotNet.Attributes;

namespace Microsoft.Security.Utilities.Benchmarks
{
    public enum RegexEngine
    {
        DotNet,
        RE2,
    }

    public enum Case
    {
        // This is close to the worst case scenario for large input. Every
        // base64 alphabet char is equally likely to appear in the input, making
        // signature sniffing harder.
        HardPrefix,

        // This is close to the best case scenario. A char that does not appear
        // in any identifiable key signature is repeated in the prefix, making
        // signature sniffing easier.
        EasyPrefix,

        // This will scan secrets without prefixing them. Testing the performance against
        // small inputs.
        NoPrefix,
    }

    public abstract class SecretMaskerDetectionBenchmarks
    {
        // The size of randomized data to add as a prefix for every secret for
        // the EasyPrefix and HardPrefix cases. This is intended to make
        // positive hits less concentrated in the profiling.
        public const int SecretPrefixSize = 10 * 1024;

        // Whether to use the high performance scanner. Normally, the high
        // performance scanner is always used, but there's a test hook to turn
        // it off, which we use to see how much it is optimizing.
        [Params(true, false)]
        public bool UseHighPerformanceScanner { get; set; } = true;

        // Whether to generate correlating ids for each match. Setting this to
        // true will contribute fixed hash production overhead to all the
        // scanners. Uncomment 'Params' attribute to benchmark with and without
        // it.
        //
        //[Params(true,  false)]
        public bool GenerateCorrelatingIds { get; set; } = false;

        // The regex engine to use. The DotNet engine is faster than RE2 on
        // modern .NET, and RE2 is faster than DotNet on .NET Framework for
        // large input. Uncomment Params attribute to benchmark both engines,
        // Otherwise, we'll use the better default for the current platform.
        //
        //[Params(RegexEngine.DotNet, RegexEngine.RE2)]
        public RegexEngine RegexEngine { get; set; } =
#if NET
            RegexEngine.DotNet;
#else
            RegexEngine.RE2;
#endif

        [ParamsAllValues]
        public Case Case { get; set;} = Case.HardPrefix;

        // Use a fixed seed to ensure different runs use the same data.
        private readonly Random _rng = new Random(Seed: 42);

        protected List<string> Examples { get; private set; } = null!;
        protected SecretMasker Masker { get; private set; } = null!;
        protected abstract IEnumerable<RegexPattern> RegexPatterns { get; }

        private string GeneratePrefix(int size, bool random)
        {
            string prefix;

            if (random)
            {
                var data = new byte[size / 4 * 3]; // Account for base64 encoding overhead.
                _rng.NextBytes(data);
                prefix = Convert.ToBase64String(data);
            }
            else
            {
                prefix = new string('%', size);
            }

            if (prefix.Length != size)
            {
                throw new InvalidOperationException("Something is wrong in math above.");
            }

            return prefix;
        }

        private List<string> GenerateExamples(bool random, int prefixSize)
        {
            var examples = new List<string>();
            var prefix = GeneratePrefix(prefixSize, random);

            foreach (var pattern in RegexPatterns)
            {
                foreach (var example in pattern.GenerateTruePositiveExamples())
                {
                    examples.Add($"{prefix} {example}");
                }
            }

            return examples;
        }

        [GlobalSetup]
        public void Setup()
        {
            Examples = Case switch
            {
                Case.HardPrefix => GenerateExamples(random: true, SecretPrefixSize),
                Case.EasyPrefix => GenerateExamples(random: false, SecretPrefixSize),
                Case.NoPrefix => GenerateExamples(random: false, 0),
                _ => throw new ArgumentOutOfRangeException(nameof(Case), "Unknown case"),
            };

            Masker = new SecretMasker(RegexPatterns,
                                      GenerateCorrelatingIds,
                                      RegexEngine == RegexEngine.DotNet ? CachedDotNetRegex.Instance : RE2RegexEngine.Instance);

            if (!UseHighPerformanceScanner)
            {
                Masker.DisableHighPerformanceScannerForTests();
            }
        }

        [Benchmark]
        public void DetectSecrets()
        {
            foreach (string example in Examples)
            {
                int count = Masker.DetectSecrets(example).Count();
                if (count != 1)
                {
                    throw new InvalidOperationException("Failed to detect example.");
                }
            }
        }
    }
}
