// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using FluentAssertions;
using FluentAssertions.Execution;
using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass, ExcludeFromCodeCoverage]
    public class IdentifiableScanTests
    {
        [TestMethod]
        public void CommonAnnotatedSecurityKey_PrefixOrSuffix_ScanTest()
        {
            using var assertionScope = new AssertionScope();

            var cask = new UnclassifiedLegacyCommonAnnotatedSecurityKey();
            var examples = cask.GenerateTruePositiveExamples().ToList();

            using var masker =
                new SecretMasker(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                                 generateCorrelatingIds: false);

            foreach (string example in examples)
            {
                string exampleWithPrefixOrSuffix = "https://" + example;

                int found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);

                exampleWithPrefixOrSuffix = example + "@azuredevops.com";

                found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);

                exampleWithPrefixOrSuffix = "https://" + example + "@azuredevops.com";

                found = masker.DetectSecrets(exampleWithPrefixOrSuffix).Count();
                found.Should().Be(1);
            }
        }

        [TestMethod]
        public void IdentifiableScan_IdentifiableKeys()
        {
            int iterations = 1;

            using var assertionScope = new AssertionScope();

            using var masker = new SecretMasker(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                                                generateCorrelatingIds: false);

            foreach (RegexPattern pattern in WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys)
            {
                var identifiable = pattern as IIdentifiableKey;
                if (identifiable == null) { continue; }

                foreach (ulong seed in identifiable.ChecksumSeeds)
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (string signature in identifiable.Signatures!)
                        {
                            // Special case: Azure Search identifiable keys must be base62 encoded.
                            bool isBase62 = signature == IdentifiableMetadata.AzureSearchSignature;
                            string key;
                            do
                            {
                                key = IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                                  identifiable.KeyLength,
                                                                                  signature,
                                                                                  identifiable.EncodeForUrl);
                            } while (isBase62 && key.IndexOfAny(['-', '_', '/', '+']) >= 0);

                            string moniker = pattern.GetMatchMoniker(key);
                            moniker.Should().NotBeNull(because: $"{pattern.Name} should produce a moniker using '{key}'");

                            int found = masker.DetectSecrets(key).Count();
                            found.Should().Be(1, because: $"{moniker} should match against '{key}' a single time, not {found} time(s)");
                        }
                    }
                }
            }
        }

        [TestMethod]
        public void IdentifiableScan_BehaviorMatchesStandardScanner()
        {
            using var assertionScope = new AssertionScope();

            var highPerformancePatterns = WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys.Where(p => p is IHighPerformanceScannableKey).ToList();

            foreach (bool generateCorrelatingIds in new[] { true, false })
            {
                using var standardMasker = new SecretMasker(highPerformancePatterns, generateCorrelatingIds);
                standardMasker.DisableHighPerformanceScannerForTests();

                using var highPerformanceMasker = new SecretMasker(highPerformancePatterns, generateCorrelatingIds);

                foreach (RegexPattern pattern in highPerformancePatterns)
                {
                    IEnumerable<string> allExamples = pattern.GenerateTruePositiveExamples().Concat(pattern.GenerateFalsePositiveExamples());

                    foreach (string example in allExamples)
                    {
                        var standardDetections = standardMasker.DetectSecrets(example).ToList();

                        var highPerformanceDetections = highPerformanceMasker.DetectSecrets(example).ToList();

                        highPerformanceDetections.Should().BeEquivalentTo(standardDetections,
                            options => options.WithStrictOrdering(),
                            because: $"the high-performance scanner should match the standard scanner for example '{example}' from '{pattern.Id}.{pattern.Name}.");
                    }
                }
            }
        }
    }
}
