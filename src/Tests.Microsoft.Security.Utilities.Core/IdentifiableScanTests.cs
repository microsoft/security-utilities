// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class IdentifiableScanTests
    {
        [TestMethod]
        public void IdentifiableScan_AzureCacheAdHocFiresOnce()
        {
            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            masker.Start();

            string doubleAzCa = "8Ht8juqPlWFke0o5KOxQ+oprdPBxZEanQAzCaAzCakQ=";

            using var stream = new MemoryStream(Encoding.UTF8.GetBytes(doubleAzCa));
            var buffer = new byte[85 * 1024];
            var text = new byte[256];

            for (; ; )
            {
                var read = stream.Read(buffer, 0, buffer.Length);

                if (read == 0)
                {
                    break;
                }

                masker.Scan(buffer, read);
            }

            masker.PossibleMatches.Should().Be(1, because: "Azure Cache pattern should only fire a single detection");
        }


        [TestMethod]
        public void IdentifiableScan_IdentifiableKeys()
        {
            int iterations = 1000;

            using var assertionScope = new AssertionScope();

            var masker = new IdentifiableScan(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                              generateCorrelatingIds: false);

            foreach (var pattern in WellKnownRegexPatterns.HighConfidenceSecurityModels)
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
