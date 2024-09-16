// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

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
        public void IdentifiableScan_IdentifiableKeys()
        {
            int iterations = 1000;

            using var assertionScope = new AssertionScope();

            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            foreach (var pattern in WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys)
            {
                var identifiable = pattern as IIdentifiableKey;
                if (identifiable == null) { continue; }

                foreach (ulong seed in identifiable.ChecksumSeeds)
                {
                    for (int i = 0; i < iterations; i++)
                    {
                        foreach (string signature in identifiable.Signatures!)
                        {
                            string key = IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                                     identifiable.KeyLength,
                                                                                     signature,
                                                                                     identifiable.EncodeForUrl);

                            string moniker = pattern.GetMatchMoniker(key);
                            moniker.Should().NotBeNull(because: $"{pattern.Name} should produce a moniker using '{key}'");

                            int found = masker.DetectSecrets(key).Count();
                            found.Should().Be(1, because: $"{moniker} should match against '{key}' a single time, not {found} time(s)");
                        }
                    }
                }
            }
        }
    }
}
