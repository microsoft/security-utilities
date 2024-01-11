// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class SecretMaskerTests
    {
        [TestMethod]
        public void TryClassify_HighConfidenceSecurityModels()
        {
            ValidateSecurityModels(WellKnownPatterns.HighConfidenceMicrosoftSecurityModels, lowEntropyModels: true);
        }

        [TestMethod]
        public void TryClassify_LowConfidenceSecurityModels()
        {
            ValidateSecurityModels(WellKnownPatterns.LowConfidenceMicrosoftSecurityModels, lowEntropyModels: true);
        }

        private void ValidateSecurityModels(IEnumerable<RegexPattern> patterns, bool lowEntropyModels)
        {
            // These tests generate randomized values. It may be useful to
            // bump up the # of iterations on an ad hoc basis to flush
            // out non-deterministic failures (typically based on the
            // characters chosen from the secret alphabet for the pattern).
            for (int i = 0; i < 1; i++)
            {
                using var scope = new AssertionScope();

                foreach (bool generateSha256Hashes in new[] { true, false })
                {
                    using var secretMasker = new SecretMasker(patterns, generateSha256Hashes);

                    foreach (var pattern in patterns)
                    {
                        foreach (string secretValue in pattern.GenerateTestExamples())
                        {
                            string moniker = pattern.GetMatchMoniker(secretValue);
                            string sha256Hash = RegexPattern.GenerateSha256Hash(secretValue);

                            // 1. All generated test patterns should be detected by the masker.
                            secretMasker.DetectSecrets(secretValue).Count().Should().Be(1);
                            Detection detection = secretMasker.DetectSecrets(secretValue).FirstOrDefault();
                            detection.Should().NotBe(new Detection());

                            // 2. All identifiable or high confidence findings should be marked as high entropy.
                            bool result = lowEntropyModels ? true : detection.Metadata.HasFlag(DetectionMetadata.HighEntropy);
                            result.Should().BeTrue(because: $"{moniker} finding should be classified as high entropy");

                            // 3. All high entropy secret kinds should generate a fingerprint, but only
                            //    if the masker was initialized to produce them. Every low entropy model
                            //    should refuse to generate a fingerprint, no matter how the masker is configured.
                            detection.Sha256Hash.Should().Be(generateSha256Hashes && lowEntropyModels ? sha256Hash : null);

                            // 4. Moniker that flows to classified secret should match the detection.
                            result = detection.Moniker.Equals(moniker);
                            result.Should().BeTrue(because: $"{moniker} finding should not be reported as {detection.Moniker} for test data {secretValue}");
                        }
                    }
                }
            }
        }
    }
}