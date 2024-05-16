// Copyright(c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions.Execution;

using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;

namespace Tests.Microsoft.Security.Utilities.Core
{
    [TestClass]
    public class IdentifiableScanTests
    {
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
                        string key = IdentifiableSecrets.GenerateBase64KeyHelper(seed,
                                                                                 identifiable.KeyLength,
                                                                                 identifiable.Signature,
                                                                                 identifiable.EncodeForUrl);


                    }
                }
            }
        }
    }
}
