// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
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
        public void WellKnownRegexPatterns_AllRulesProvideCreatedVersion()
        {
            using var assertionScope = new AssertionScope();

            var patterns = GetAllPatterns();
            foreach (RegexPattern pattern in patterns)
            {
                bool result = pattern.CreatedVersion == null;
                result.Should().BeFalse(because: $"pattern '{pattern.GetType().Name}' should declare an explicit 'CreatedVersion'");
            }
        }

        [TestMethod]
        public void WellKnownRegexPatterns_AllRuleIdsAndNamesAreUnique()
        {
            using var assertionScope = new AssertionScope();

            var patterns = GetAllPatterns();

            HashSet<string> ruleIdsObserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            HashSet<string> ruleNamesObserved = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (RegexPattern pattern in patterns)
            {
                if (pattern.Id == "SEC101/199")
                {
                    // These rules are an oddball. Event Grid has two version of
                    // identifiable check, 'AzureEventGridIdentifiableKey' and
                    // 'AzureEventGridLegacyCommonAnnotatedSecurityKey'.
                    continue;
                }

                bool result = ruleIdsObserved.Contains(pattern.Id);
                result.Should().BeFalse(because: $"Pattern '{pattern.GetType().Name}' should not share its Id with another rule: '{pattern.Id}'");

                result = ruleNamesObserved.Contains(pattern.Name);
                result.Should().BeFalse(because: $"Pattern '{pattern.GetType().Name}' should not share its Name with another rule: '{pattern.Name}'");

                ruleIdsObserved.Add(pattern.Id);
                ruleNamesObserved.Add(pattern.Name);
            }
        }

        [TestMethod]
        public void WellKnownRegexPatterns_MonikerRuleIdsAndNamesMatchDeclared()
        {
            using var assertionScope = new AssertionScope();

            var patterns = GetAllPatterns();

            foreach (RegexPattern pattern in patterns)
            {
                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    var detection = pattern.GetDetections(example, generateCrossCompanyCorrelatingIds: false).FirstOrDefault();
                    Assert.AreNotEqual(default, detection);

                    string preciseMatch = example.Substring(detection.Start, detection.Length);

                    var idAndName = pattern.GetMatchIdAndName(preciseMatch);

                    Assert.AreEqual(pattern.Id, idAndName.Item1,
                                    $"Pattern '{pattern.GetType().Name}' id did not match 'GetMatchIdAndName' result");

                    Assert.AreEqual(pattern.Name, idAndName.Item2,
                                    $"Pattern '{pattern.GetType().Name}' name did not match 'GetMatchIdAndName' result");
                }
            }
        }

        [TestMethod]
        public void WellKnownRegexPatterns_GetMatchMonikerHardenedForOutOfOrderExecution()
        {
            using var assertionScope = new AssertionScope();

            var patterns = GetAllPatterns();

            var masker = new SecretMasker(patterns,
                                          generateCorrelatingIds: true,
                                          RE2RegexEngine.Instance);

            foreach (RegexPattern pattern in patterns)
            {
                foreach (string example in pattern.GenerateTruePositiveExamples())
                {
                    // It is not obvious, but this is a test to ensure this call
                    // does not raise exceptions. This API calls into 
                    // 'GetMatchIdAndName' which itself may return null, indicating
                    // that post-processing has determined that the pattern is not
                    // a match. Because we are in the context of producing positive
                    // test cases, this means that the test pattern contains data
                    // that itself will be removed on the preliminary match operation.
                    // We will therefore call this code agains to ensure that it
                    // is no longer null post-detection.
                    string moniker = pattern.GetMatchMoniker(example);

                    var detection = masker.DetectSecrets(example).FirstOrDefault();

                    bool result = detection != default;
                    result.Should().BeTrue(because: $"pattern '{pattern.GetType().Name}' should match '{example}'");

                    string matched = example.Substring(detection.Start, detection.End - detection.Start);
                    moniker = pattern.GetMatchMoniker(matched);
                    moniker.Should().NotBeNull(because: $"'{matched}' should produce a non-null moniker for {pattern.GetType().Name}' test data");
                }
            }
        }

        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllPatternsExpressConfidence()
        {
            for (int i = 0; i < 1; i++)
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
            for (int i = 0; i < 1; i++)
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
                WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                WellKnownRegexPatterns.DataClassification,
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

        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllPatternsHaveCorrectCaptureGroups()
        {
            using var assertionScope = new AssertionScope();

            var rulesets = new[]{
                WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                WellKnownRegexPatterns.DataClassification,
            };

            foreach (IEnumerable<RegexPattern> ruleset in rulesets)
            {
                foreach (RegexPattern pattern in ruleset)
                {
                    Regex regex = CachedDotNetRegex.GetOrCreateRegex(pattern.Pattern, RegexOptions.ExplicitCapture);
                    var groupNames = regex.GetGroupNames().Where(g => !int.TryParse(g, out _)).ToArray();
                    if (groupNames.Length == 0)
                    {
                        continue;
                    }

                    groupNames.Length.Should().Be(1, because: $"Pattern '{pattern.GetType().Name}' should not have more than one capture group");
                    groupNames[0].Should().Be("refine", because: $"Pattern '{pattern.GetType().Name}' capture group should be named 'refine'");

                    pattern.Pattern.Should()
                        .Contain("(?P<refine>",
                                 because: $"Pattern '{pattern.GetType().Name}' should contain an RE2-compatible '(?P<refine>...)' named capture group");
                }
            }
        }

        [TestMethod]
        public void WellKnownRegexPatterns_EnsureAllPatternsHaveSupersetOfDefaultOptions()
        {
            using var assertionScope = new AssertionScope();
            var patterns = GetAllPatterns();
            foreach (RegexPattern pattern in patterns)
            {
                (pattern.RegexOptions & RegexDefaults.DefaultOptions).Should()
                    .Be(RegexDefaults.DefaultOptions,
                        because: "All built-in patterns should use the default regex options. Additional options and may be added, but no default options should be removed.");
            }
        }

        private static List<RegexPattern> GetAllPatterns()
        {
            var patterns = new List<RegexPattern>();

            patterns.AddRange(WellKnownRegexPatterns.DataClassification);
            patterns.AddRange(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys);
            patterns.AddRange(WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys);

            return patterns;
        }
    }
}
