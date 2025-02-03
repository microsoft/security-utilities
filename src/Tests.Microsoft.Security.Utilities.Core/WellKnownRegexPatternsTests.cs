// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Runtime.Remoting.Contexts;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities
{
    [TestClass, ExcludeFromCodeCoverage]
    public class WellKnownRegexPatternsTests
    {
        /// <summary>
        /// This list should be empty.
        /// If it isn't, then it indicates failures associated with the corresponding rules.
        /// Check https://github.com/microsoft/security-utilities/issues for open issues.
        /// </summary>
        private readonly List<string> WellKnownRegexPatternsExclusionList = new()
        {
            "SEC101/127.UrlCredentials",
            "SEC101/109.AzureContainerRegistryLegacyKey"
        };

        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllPatternsExpressConfidence()
        {
            for (int i = 0; i < 1000; i++)
            {
                using var assertionScope = new AssertionScope();

                var rulesets = new[] {
                    WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                    WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys
                };

                var missingConfidence = new List<string>();

                foreach (IEnumerable<RegexPattern> ruleset in rulesets)
                {
                    foreach (RegexPattern pattern in ruleset)
                    {
                        foreach (string example in pattern.GenerateTruePositiveExamples())
                        {
                            string standaloneSecret =
                                CachedDotNetRegex.Instance.Matches(example,
                                                                   pattern.Pattern,
                                                                   captureGroup: "refine").First().Value;


                            string moniker = pattern.GetMatchMoniker(standaloneSecret);

                            if (pattern.DetectionMetadata.HasFlag(DetectionMetadata.LowConfidence) ||
                                pattern.DetectionMetadata.HasFlag(DetectionMetadata.MediumConfidence) ||
                                pattern.DetectionMetadata.HasFlag(DetectionMetadata.HighConfidence))
                            {
                                continue;
                            }

                            missingConfidence.Add(moniker);

                            // We only require a single match to identify missing confidence,
                            // which is expressed at the pattern level.
                            break;
                        }
                    }
                }

                missingConfidence.Should().HaveCount(0, because: $"{string.Join(", ", missingConfidence)} are missing an explicit confidence level");
            }
        }


        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllMediumConfidenceOrBetterPatternsDefineSignatures()
        {
            for (int i = 0; i < 1000; i++)
            {
                using var assertionScope = new AssertionScope();

                var rulesets = new[] {
                    WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                    WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys
                };

                var missingSignatures = new List<string>();

                foreach (IEnumerable<RegexPattern> ruleset in rulesets)
                {
                    foreach (RegexPattern pattern in ruleset)
                    {
                        foreach (string example in pattern.GenerateTruePositiveExamples())
                        {
                            string standaloneSecret =
                                CachedDotNetRegex.Instance.Matches(example,
                                                                   pattern.Pattern,
                                                                   captureGroup: "refine").First().Value;

                            string moniker = pattern.GetMatchMoniker(standaloneSecret);

                            if (pattern.DetectionMetadata.HasFlag(DetectionMetadata.LowConfidence) ||
                                (pattern.Signatures != null && pattern.Signatures.Any()))
                            {
                                continue;
                            }

                            missingSignatures.Add(moniker);

                            // We only require a single match to identify missing confidence,
                            // which is expressed at the pattern level.
                            break;
                        }
                    }
                }

                missingSignatures.Should().HaveCount(0, because: $"{string.Join(", ", missingSignatures)} are medium or high confidence patterns that should declare one or more signatures for pre-filtering");
            }
        }

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
                        string standaloneSecret =
                            CachedDotNetRegex.Instance.Matches(example,
                                                               pattern.Pattern,
                                                               captureGroup: "refine").First().Value;

                        wellKnownMonikers.Add(pattern.GetMatchMoniker(standaloneSecret));
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
                    string standaloneSecret =
                        CachedDotNetRegex.Instance.Matches(example,
                                                           pattern.Pattern,
                                                           captureGroup: "refine").First().Value;

                    string moniker = pattern.GetMatchMoniker(standaloneSecret);
                    if (!wellKnownMonikers.Contains(moniker))
                    {
                        unrecognizedMonikers.Add(moniker);
                    }

                }
            }

            foreach (string unrecognizedMoniker in unrecognizedMonikers)
            {
                if (WellKnownRegexPatternsExclusionList.Contains(unrecognizedMoniker))
                {
                    continue;
                }

                false.Should().BeTrue(because: $"'{unrecognizedMoniker}' should be referenced by a WellKnownPatterns ruleset");
            }
        }
    }
}
