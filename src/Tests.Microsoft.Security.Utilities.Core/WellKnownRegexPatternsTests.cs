// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Reflection;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass]
    public class WellKnownRegexPatternsTests
    {
        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllPatternsAreReferenced()
        {
            using var assertionScope = new AssertionScope();

            var rulesets = new[]{
                WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys
            };

            HashSet<string> wellKnownMonikers = new HashSet<string>();

            foreach (IEnumerable<RegexPattern> ruleset in rulesets)
            {
                foreach (RegexPattern pattern in ruleset)
                {
                    foreach (string example in pattern.GenerateTruePositiveExamples())
                    {
                        wellKnownMonikers.Add(pattern.GetMatchMoniker(example));
                    }
                }
            }

            Assembly coreAssembly = typeof(WellKnownRegexPatterns).Assembly;

            HashSet<string> unrecognizedMonikers = new HashSet<string>();

            foreach (Type type in coreAssembly.GetTypes())
            {
                if (type.IsAbstract || !type.IsSubclassOf(typeof(RegexPattern)))
                {
                    continue;
                }

                RegexPattern pattern = (RegexPattern)Activator.CreateInstance(type);

                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    string moniker = pattern.GetMatchMoniker(example);
                    if (!wellKnownMonikers.Contains(moniker))
                    {
                        unrecognizedMonikers.Add(moniker);
                    }

                }
            }

            foreach (string unrecognizedMoniker in unrecognizedMonikers)
            {
                false.Should().BeTrue(because: $"'{unrecognizedMoniker}' should be referenced by a WellKnownPatterns ruleset");
            }
        }
    }
}
