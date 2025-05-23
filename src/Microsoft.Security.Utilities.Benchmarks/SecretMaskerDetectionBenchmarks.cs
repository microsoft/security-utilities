﻿// Copyright (c) Microsoft. All rights reserved.
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
        /// <summary>
        /// This is close to the worst case scenario for large input. Every
        /// base64 alphabet char is equally likely to appear in the input,
        /// making signature sniffing harder.
        /// </summary>
        HardPrefix,

        /// <summary>
        /// This is close to the best case scenario. A char that does not appear
        /// in any identifiable key signature is repeated in the prefix, making
        /// signature sniffing easier.
        /// </summary>
        EasyPrefix,

        /// <summary>
        /// This will scan secrets without prefixing them in order to test the
        /// performance against small inputs.
        /// </summary>
        NoPrefix,
    }

    public abstract class SecretMaskerDetectionBenchmarks
    {
        /// <summary>
        /// The length in chars of randomized data to add as a prefix for every
        /// secret for the <see cref="Case.EasyPrefix"/> and <see
        /// cref="Case.HardPrefix"/> cases. This is intended to make positive
        /// hits less concentrated in the profiling.
        /// </summary>
        public const int SecretPrefixLength = 100 * 1000;

        /// <summary>
        /// Whether to use the high performance scanner. Normally, the high
        /// performance scanner is always used, but there's a test hook to turn
        /// it off, which we use to see how much it is optimizing.
        /// </summary>
        //[Params(true, false)]
        public bool UseHighPerformanceScanner { get; set; } = true;

        /// <summary>
        /// Whether to generate correlating ids for each match. Setting this to
        /// true will contribute fixed hash production overhead to all the
        /// scanners. Uncomment 'Params' attribute to benchmark with and without
        /// it.
        /// </summary>
        //[Params(true,  false)]
        public bool GenerateCorrelatingIds { get; set; } = false;

        /// <summary>
        /// The regex engine to use. The DotNet engine is faster than RE2 on
        /// modern .NET, and RE2 is faster than DotNet on .NET Framework for
        /// large input. Uncomment Params attribute to benchmark both engines,
        /// Otherwise, we'll use the better default for the current platform.
        /// </summary>
        //[Params(RegexEngine.DotNet, RegexEngine.RE2)]
        public RegexEngine RegexEngine { get; set; } =
#if NET
            RegexEngine.DotNet;
#else
            RegexEngine.RE2;
#endif

        [ParamsAllValues]
        public Case Case { get; set; } = Case.HardPrefix;

        // Use a fixed seed to ensure different runs use the same data.
        private readonly Random _rng = new Random(Seed: 42);

        protected List<string> Examples { get; private set; } = null!;
        protected SecretMasker Masker { get; private set; } = null!;
        protected abstract IEnumerable<RegexPattern> RegexPatterns { get; }

        private string GeneratePrefix(int length, bool random)
        {
            string prefix;

            if (random)
            {
                int byteCount = Base64CharsToBytes(length);
                byte[] data = new byte[byteCount];
                _rng.NextBytes(data);
                prefix = Convert.ToBase64String(data).Substring(0, length);
            }
            else
            {
                prefix = new string('%', length);
            }

            if (prefix.Length != length)
            {
                throw new InvalidOperationException("Produced prefix with incorrect length.");
            }

            return prefix;
        }

        private static int Base64CharsToBytes(int chars)
        {
            return RoundUpToMultipleOf(chars, 4) / 4 * 3;
        }

        private static int RoundUpToMultipleOf(int value, int multiple)
        {
            return (value + multiple - 1) / multiple * multiple;
        }

        private List<string> GenerateExamples(bool random, int prefixLength, int examplesCount = 870)
        {
            var examples = new List<string>();
            string prefix = GeneratePrefix(prefixLength, random);

            var exampleGenerators = new List<IEnumerator<string>>();

            foreach (RegexPattern pattern in RegexPatterns)
            {
                IEnumerator<string> enumerator = pattern.GenerateTruePositiveExamples().GetEnumerator();
                exampleGenerators.Add(enumerator);
                enumerator.MoveNext();
            }

            while (examples.Count < examplesCount)
            {
                foreach (IEnumerator<string> exampleGenerator in exampleGenerators)
                {
                    if (exampleGenerator.Current != null)
                    {
                        examples.Add($"{prefix} {exampleGenerator.Current}");
                        exampleGenerator.MoveNext();
                    }

                    if (examples.Count >= examplesCount)
                    {
                        break;
                    }
                }
            }

            return examples;
        }

        [GlobalSetup]
        public void Setup()
        {
            Examples = Case switch
            {
                Case.HardPrefix => GenerateExamples(random: true, SecretPrefixLength),
                Case.EasyPrefix => GenerateExamples(random: false, SecretPrefixLength),
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
