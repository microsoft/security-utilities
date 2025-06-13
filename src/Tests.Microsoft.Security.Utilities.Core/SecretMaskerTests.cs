// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities;

[TestClass, ExcludeFromCodeCoverage]
public class SecretMaskerTests
{
    [TestMethod]
    public void SecretMasker_PreciselyClassifiedSecurityKeys_Detections()
    {
        ValidateSecurityModelsDetections(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                                         preciseClassifications: true);
    }

    [TestMethod]
    public void SecretMasker_UnclassifiedPotentialSecurityKeys_Detections()
    {
        // TODO: allowMultipleFindings due to https://github.com/microsoft/security-utilities/issues/95
        ValidateSecurityModelsDetections(WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                                         preciseClassifications: false,
                                         allowAdditionalFindings: true);
    }

    [TestMethod]
    public void SecretMasker_DataClassification_Detections()
    {
        ValidateSecurityModelsDetections(WellKnownRegexPatterns.DataClassification,
                                         preciseClassifications: false);
    }

    private void ValidateSecurityModelsDetections(IEnumerable<RegexPattern> patterns, bool preciseClassifications, bool allowAdditionalFindings = false)
    {
        // These tests generate randomized values. It may be useful to
        // bump up the # of iterations on an ad hoc basis to flush
        // out non-deterministic failures (typically based on the
        // characters chosen from the secret alphabet for the pattern).
        for (int i = 0; i < 1; i++)
        {
            using var scope = new AssertionScope();

            foreach ((IRegexEngine engine, bool useMemory) in new[] {
                (RE2RegexEngine.Instance, false), 
                (CachedDotNetRegex.Instance, false),
#if NET
                (CachedDotNetRegex.Instance, true)
#endif
            })
            {
                foreach (bool generateCrossCompanyCorrelatingIds in new[] { true, false })
                {
                    using var secretMasker = new SecretMasker(patterns, generateCrossCompanyCorrelatingIds, engine);

                    foreach (RegexPattern pattern in patterns)
                    {
                        string moniker = $"{pattern.Id}.{pattern.Name}";

                        foreach (string testExample in pattern.GenerateTruePositiveExamples())
                        {
                            string context = testExample;
                            var matches = CachedDotNetRegex.Instance.Matches(context, pattern.Pattern, captureGroup: "refine").ToList();
                            bool result = matches.Count == 1;
                            result.Should().BeTrue(because: $"pattern {pattern.Id} should match '{context}' exactly once");

                            string standaloneSecret = matches[0].Value;

                            List<Detection> detections;
#if NET
                            if (useMemory)
                            {
                                detections = secretMasker.DetectSecrets(new ReadOnlyMemory<char>(context.ToCharArray())).ToList();
                            }
                            else
#endif
                            {
                                Assert.IsFalse(useMemory, "Can't test non-existent memory overload on .NET Framework.");
                                detections = secretMasker.DetectSecrets(context).ToList();
                            }

                            if (allowAdditionalFindings)
                            {
                                // TODO duplication in analysis has snuck in.
                                // https://github.com/microsoft/security-utilities/issues/95
                                detections = detections.Where(d => d.Moniker == moniker && context.Substring(d.Start, d.Length) == standaloneSecret).ToList();
                            }

                            detections.Count.Should().Be(1, because: $"'{context}' should result in a single '{moniker}' finding");

                            Detection detection = detections[0];
                            detection.Moniker.Should().Be(moniker);

                            // 2. All identifiable or high confidence findings should be marked as high entropy.
                            if (preciseClassifications)
                            {
                                result = detection.Metadata.HasFlag(DetectionMetadata.HighEntropy);
                                result.Should().BeTrue(because: $"{moniker} finding should be classified as high entropy");
                            }

                            // 3. All high entropy secret kinds should generate a cross-company correlating id,
                            //    but only if the masker was initialized to produce them. Every low entropy model
                            //    should refuse to generate a c3id, no matter how the masker is configured.
                            string c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(standaloneSecret);
                            string actualC3id = detection.CrossCompanyCorrelatingId;
                            string expectedC3id = generateCrossCompanyCorrelatingIds &&
                                                  detection.Metadata.HasFlag(DetectionMetadata.HighEntropy)
                                                        ? c3id
                                                        : null;

                            result = object.Equals(expectedC3id, actualC3id);
                            result.Should().BeTrue(because: $"'{expectedC3id}' redaction token expected for '{moniker}' instance but observed '{actualC3id}'");

                            // 4. All high entropy secret kinds should generate a fingerprint, but only
                            //    if the masker was initialized to produce them. Every low entropy model
                            //    should refuse to generate a fingerprint, no matter how the masker is configured.
                            string actualRedactionToken = detection.RedactionToken;
                            string expectedRedactionToken = generateCrossCompanyCorrelatingIds &&
                                                            detection.Metadata.HasFlag(DetectionMetadata.HighEntropy)
                                                                ? $"{pattern.Id}:{c3id}"
                                                                : "+++";

                            result = actualRedactionToken.Equals(expectedRedactionToken);
                            result.Should().BeTrue(because: $"'{expectedRedactionToken}' redaction token expected for '{moniker}' finding but observed '{actualRedactionToken}'");

                            // 5. Moniker that flows to classified secret should match the detection.
                            result = detection.Moniker.Equals(moniker);
                            result.Should().BeTrue(because: $"{moniker} finding should not be reported as {detection.Moniker} for test data {context}");
                        }

                        foreach (string testExample in pattern.GenerateFalsePositiveExamples())
                        {
                            // 6. All generated false positive test patterns should not return any detections matching their moniker.
                            IEnumerable<Detection> detections;
#if NET
                            if (useMemory)
                            {
                                detections = secretMasker.DetectSecrets(new ReadOnlyMemory<char>(testExample.ToCharArray())).ToList();
                            }
                            else
#endif
                            {
                                Assert.IsFalse(useMemory, "Can't test non-existent memory overload on .NET Framework.");
                                detections = secretMasker.DetectSecrets(testExample).ToList();
                            }

                            detections = secretMasker.DetectSecrets(testExample).Where(d => d.Moniker == moniker);
                            detections.Should().BeEmpty(because: $"false positive example '{testExample}' should not result in any findings for '{moniker}'");
                        }
                    }
                }
            }
        }
    }

    [TestMethod]
    public void SecretMasker_HighConfidenceSecurityModels_Masking()
    {
        foreach (IRegexEngine engine in new IRegexEngine[] { RE2RegexEngine.Instance, CachedDotNetRegex.Instance })
        {
            ValidateSecurityModelsMasking(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels,
                                          engine,
                                          lowEntropyModels: false);
        }
    }

    [TestMethod]
    public void SecretMasker_LowConfidenceSecurityModels_Masking()
    {
        foreach (IRegexEngine engine in new IRegexEngine[] { RE2RegexEngine.Instance, CachedDotNetRegex.Instance })
        {
            ValidateSecurityModelsMasking(new[] { new LooseSasSecret() },
                                          engine,
                                          lowEntropyModels: false);
        }
    }

    private void ValidateSecurityModelsMasking(IEnumerable<RegexPattern> patterns, IRegexEngine engine, bool lowEntropyModels)
    {
        using var assertionScope = new AssertionScope();

        // These tests generate randomized values. It may be useful to
        // bump up the # of iterations on an ad hoc basis to flush
        // out non-deterministic failures (typically based on the
        // characters chosen from the secret alphabet for the pattern).
        for (int i = 0; i < 1; i++)
        {
            foreach (bool generateCrossCompanyCorrelatingIds in new[] { true, false })
            {
                using var secretMasker = new SecretMasker(patterns, generateCrossCompanyCorrelatingIds, engine);

                foreach (RegexPattern pattern in patterns)
                {
                    if (!lowEntropyModels && !pattern.DetectionMetadata.HasFlag(DetectionMetadata.HighEntropy))
                    {
                        continue;
                    }

                    string moniker = $"{pattern.Id}.{pattern.Name}";

                    foreach (string testExample in pattern.GenerateTruePositiveExamples())
                    {
                        // 1. All generated test patterns should be detected by the masker.
                        var detections = new List<Detection>();
                        string redacted = secretMasker.MaskSecrets(testExample, detections.Add);

                        Detection detection = detections.FirstOrDefault();
                        bool result = detection != null;
                        result.Should().BeTrue(because: $"'{testExample}' should contain a secret detected by at least one rule");

                        string standaloneSecret = testExample.Substring(detection.Start, detection.Length);
                        result = redacted.Equals(testExample);
                        result.Should().BeFalse(because: $"'{standaloneSecret}' for '{moniker}' should be redacted from scan text");

                        string expectedRedactedValue = generateCrossCompanyCorrelatingIds
                            ? $"{pattern.Id}:{RegexPattern.GenerateCrossCompanyCorrelatingId(standaloneSecret)}"
                            : RegexPattern.FallbackRedactionToken;

                        redacted.Should().Contain(expectedRedactedValue, because: $"generate correlating ids == {generateCrossCompanyCorrelatingIds} for '{standaloneSecret}'");
                    }

                    foreach (string testExample in pattern.GenerateFalsePositiveExamples())
                    {
                        string secretValue = testExample;

                        // 1. All generated false positive test patterns should
                        //  not result in a mask operation.
                        string redacted = secretMasker.MaskSecrets(secretValue);
                        bool result = redacted.Equals(secretValue);
                        result.Should().BeTrue(because: $"'{secretValue}' for '{moniker}' should not be redacted from scan text");
                    }
                }
            }
        }
    }

    private SecretMasker InitializeTestMasker(bool generateCorrelatingIds = false)
    {
        var testSecretMasker = new SecretMasker(new[] { new UrlCredentials() },
                                                generateCorrelatingIds: generateCorrelatingIds);
        return testSecretMasker;
    }

#if NET
    [TestMethod]
    public void SecretMasker_ScansAndMasksStringSegmentWithMatches()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("testvalue");
        secretMasker.AddRegex(new RegexPattern("", "", "", DetectionMetadata.None, pattern: "testregex"));
        string fullString = "testvalue tesregex --> testvalue testregex <-- testvalue testregex";
        int start = fullString.IndexOf("-->") + 3;
        int length = fullString.IndexOf("<--") - start;
        ReadOnlyMemory<char> segment = fullString.AsMemory(start, length);

        var detectionsFromDetectSecrets = secretMasker.DetectSecrets(segment).ToList();
        SecretMasker.SortDetectionsForMasking(detectionsFromDetectSecrets);

        var detectionsFromMaskSecrets = new List<Detection>();
        string masked = secretMasker.MaskSecrets(segment, detectionsFromMaskSecrets.Add);
        Assert.AreEqual(" *** +++ ", masked);

        detectionsFromDetectSecrets.Should().BeEquivalentTo(detectionsFromMaskSecrets, options => options.WithStrictOrdering());
        List<Detection> detections = detectionsFromMaskSecrets;

        Assert.AreEqual(2, detections.Count);
        Assert.AreEqual(1, detections[0].Start);
        Assert.AreEqual(9, detections[0].Length);
        Assert.AreEqual(DetectionKind.Literal, detections[0].Kind);
        Assert.AreEqual(11, detections[1].Start);
        Assert.AreEqual(9, detections[1].Length);
        Assert.AreEqual(DetectionKind.Regex, detections[1].Kind);
    }

    [TestMethod]
    public void SecretMasker_ScansAndMasksStringSegmentWithNoMatch()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("testvalue");
        secretMasker.AddRegex(new RegexPattern("", "", "", DetectionMetadata.None, pattern: "testregex"));
        string fullString = "testvalue tesregex --> yada yada yada <-- testvalue testregex";
        int start = fullString.IndexOf("-->") + 3;
        int length = fullString.IndexOf("<--") - start;
        ReadOnlyMemory<char> segment = fullString.AsMemory(start, length);

        var detectionsFromDetectSecrets = secretMasker.DetectSecrets(segment).ToList();
        var detectionsFromMaskSecrets = new List<Detection>();
        string masked = secretMasker.MaskSecrets(segment, detectionsFromMaskSecrets.Add);
        Assert.AreEqual(" yada yada yada ", masked);

        detectionsFromDetectSecrets.Should().BeEmpty();
        detectionsFromMaskSecrets.Should().BeEmpty();
        List<Detection> detections = detectionsFromMaskSecrets;
    }
#endif

    [TestMethod]
    public void SecretMasker_UrlNotMasked()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = "https://simpledomain@example.com";
        string output = secretMasker.MaskSecrets(input);

        Assert.AreEqual(input, output);

        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_ComplexUrlNotMasked()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = "https://url.com:443/~user/foo=bar+42-18?what=this.is.an.example....~~many@&param=value";

        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(input, actual);

        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_UrlCredentialsAreMasked()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = "https://user:pass@example.com";
        string expected = "https://+++@example.com";

        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(expected, actual);

        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithSpecialCharactersMaskedCorrectly()
    {
        using SecretMasker secretMasker = InitializeTestMasker();

        string input = @"https://user:pass4';.!&*()=,$-+~@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithDigitsInNameMaskedCorrectly()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = @"https://username123:password@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithLongPasswordAndNameMaskedCorrectly()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = @"https://username_loooooooooooooooooooooooooooooooooooooooooong:password_looooooooooooooooooooooooooooooooooooooooooooooooong@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithEncodedCharactersInNameMaskedCorrectly()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = @"https://username%10%A3%F6:password123@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithEncodedAndEscapedCharactersInNameMaskedCorrectly()
    {
        using SecretMasker secretMasker = InitializeTestMasker();
        string input = @"https://username%AZP2510%AZP25A3%AZP25F6:password123@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_Encoder()
    {
        // Add encoder before values.
        using var secretMasker = new SecretMasker();
        secretMasker.AddLiteralEncoder(x => x.Replace("-", "_"));
        secretMasker.AddLiteralEncoder(x => x.Replace("-", " "));
        secretMasker.AddValue("value-1");
        secretMasker.AddValue("value-2");
        Assert.AreEqual("***", secretMasker.MaskSecrets("value-1"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value_1"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value 1"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value-2"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value_2"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value 2"));
        Assert.AreEqual("value-3", secretMasker.MaskSecrets("value-3"));

        // Add values after encoders.
        secretMasker.AddValue("value-3");
        Assert.AreEqual("***", secretMasker.MaskSecrets("value-3"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value_3"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("value 3"));
    }

    [TestMethod]
    public void SecretMasker_Encoder_EscapeJsonString()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddLiteralEncoder(WellKnownTestLiteralEncoders.EscapeJsonString);
        secretMasker.AddValue("carriage-return\r_newline\n_tab\t_backslash\\_double-quote\"");
        Assert.AreEqual("***", secretMasker.MaskSecrets("carriage-return\r_newline\n_tab\t_backslash\\_double-quote\""));
        Assert.AreEqual("***", secretMasker.MaskSecrets("carriage-return\\r_newline\\n_tab\\t_backslash\\\\_double-quote\\\""));
    }

    [TestMethod]
    public void SecretMasker_Encoder_UnescapeBackslashes()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddLiteralEncoder(WellKnownLiteralEncoders.UnescapeBackslashes);
        secretMasker.AddValue(@"abc\\def\'\""ghi\t");
        Assert.AreEqual("***", secretMasker.MaskSecrets(@"abc\\def\'\""ghi\t"));
        Assert.AreEqual("***", secretMasker.MaskSecrets(@"abc\def'""ghi" + "\t"));
    }

    [TestMethod]
    public void SecretMasker_Encoder_UriDataEscape()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddLiteralEncoder(WellKnownLiteralEncoders.UriDataEscape);
        secretMasker.AddValue("hello world");
        Assert.AreEqual("***", secretMasker.MaskSecrets("hello world"));
        Assert.AreEqual("***", secretMasker.MaskSecrets("hello%20world"));
    }

    [TestMethod]
    public void SecretMasker_Encoder_UriDataEscape_LargeString()
    {
        // Uri.EscapeDataString cannot receive a string longer than 65519 characters.
        // For unit testing we call a different overload with a smaller segment size (improve unit test speed).

        LiteralEncoder encoder = x => WellKnownLiteralEncoders.UriDataEscape(x);

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(1, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(2, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(3, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(4, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(5, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(5, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(6, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }


        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = string.Empty.PadRight(7, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = "𐐷𐐷𐐷𐐷"; // surrogate pair
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            string value = " 𐐷𐐷𐐷𐐷"; // shift by one non-surrogate character to ensure surrogate across segment boundary handled correctly
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
        }
    }

    [TestMethod]
    public void SecretMasker_HandlesEmptyInput()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue(null);
        secretMasker.AddValue(string.Empty);

        string result = secretMasker.MaskSecrets((string)null);
        Assert.AreEqual(string.Empty, result);

        result = secretMasker.MaskSecrets(string.Empty);
        Assert.AreEqual(string.Empty, result);

        IEnumerable<Detection> detections = secretMasker.DetectSecrets((string)null);
        Assert.IsTrue(!detections.Any(), "No detections expected for null input.");

        detections = secretMasker.DetectSecrets(string.Empty);
        Assert.IsTrue(!detections.Any(), "No detections expected for empty input");
    }

    [TestMethod]
    public void SecretMasker_ProvidesVersion()
    {
        var expected = new Version(FileVersionInfo.GetVersionInfo(typeof(SecretMasker).Assembly.Location).FileVersion);
        Version actual = SecretMasker.Version;
        Assert.AreEqual(expected.Major, actual.Major);
        Assert.AreEqual(expected.Minor, actual.Minor);
        Assert.AreEqual(expected.Build, actual.Build);
        Assert.AreEqual(-1, actual.Revision); // SecretMasker.Version does not include revision.
    }

    [TestMethod]
    public void SecretMasker_TestCorrelatingId()
    {
        string suffix = "00000";
        string secret = $"secret_scanning_ab85fc6f8d7638cf1c11da812da308d43_{suffix}";
        using var secretMasker = new SecretMasker(new[] { new SecretScanningSampleToken() }, generateCorrelatingIds: true);
        IEnumerable<Detection> detections = secretMasker.DetectSecrets(secret);
        detections.Count().Should().Be(1);
        Detection detection = detections.First();

        int colonIndex = detection.RedactionToken.IndexOf(':');
        string correlatingId = detection.RedactionToken.Substring(colonIndex + 1);
        correlatingId.Should().Be("0W7kMOsBl4huQu/6Rekx");
        RegexPattern.GenerateCrossCompanyCorrelatingId(secret).Should().Be(correlatingId);
    }

    [TestMethod]
    public void SecretMasker_HandlesNoMasks()
    {
        using var secretMasker = new SecretMasker();
        string input = "abc";

        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(input, actual);
    }

    [TestMethod]
    public void SecretMasker_ReplacesValue()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");

        string input = "abcdefg";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("abc***g", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleInstances()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");

        string input = "abcdefgdef";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("abc***g***", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleAdjacentInstances()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("abc");

        string input = "abcabcdef";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("***def", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleSecrets()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("bcd");
        secretMasker.AddValue("fgh");

        string input = "abcdefghi";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("a***e***i", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesOverlappingSecrets()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");
        secretMasker.AddValue("bcd");

        string input = "abcdefg";
        string result = secretMasker.MaskSecrets(input);

        // a naive replacement would replace "def" first, and never find "bcd", resulting in "abc+++g"
        // or it would replace "bcd" first, and never find "def", resulting in "a+++efg"

        Assert.AreEqual("a***g", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesAdjacentSecrets()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("efg");
        secretMasker.AddValue("bcd");

        string input = "abcdefgh";
        string result = secretMasker.MaskSecrets(input);

        // two adjacent secrets are basically one big secret

        Assert.AreEqual("a***h", result);
    }

    [TestMethod]
    public void SecretMasker_MinimumSecretLength()
    {
        using var secretMasker = new SecretMasker();
        Assert.AreEqual(0, secretMasker.MinimumSecretLength);

        // Make abcde, hijk, pqr, and xy secrets stressing different code paths
        // through adding values, literal encoders, and regexes.

        // 1. Add value
        secretMasker.AddValue("xy");

        // 2. Add encoder *after* impacted value.
        secretMasker.AddValue("1");
        secretMasker.AddLiteralEncoder(v => v.Replace("1", "pqr"));

        // 3. Add encoder *before* impacted value.
        secretMasker.AddLiteralEncoder(v => v.Replace("2", "hijk"));
        secretMasker.AddValue("2");

        // 4. Add regex
        secretMasker.AddRegex(new(id: "", name: "", label: "", patternMetadata: 0, pattern: "a.*e"));

        // Mask with increasingly large minimum secret lengths to disqualify 1 secret at a time.
        Assert.AreEqual(0, secretMasker.MinimumSecretLength);
        string input = "abcdefghijklmnopqrstuvwxyz";
        string result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fg***lmno***stuvw***z");

        secretMasker.MinimumSecretLength = 2;
        Assert.AreEqual(2, secretMasker.MinimumSecretLength);

        result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fg***lmno***stuvw***z");

        secretMasker.MinimumSecretLength = 3;
        Assert.AreEqual(3, secretMasker.MinimumSecretLength);
        result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fg***lmno***stuvwxyz");

        secretMasker.MinimumSecretLength = 4;
        Assert.AreEqual(4, secretMasker.MinimumSecretLength);
        result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fg***lmnopqrstuvwxyz");

        secretMasker.MinimumSecretLength = 5;
        Assert.AreEqual(5, secretMasker.MinimumSecretLength);
        result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fghijklmnopqrstuvwxyz");

        secretMasker.MinimumSecretLength = 6;
        Assert.AreEqual(6, secretMasker.MinimumSecretLength);
        result = secretMasker.MaskSecrets(input);
        result.Should().Be("abcdefghijklmnopqrstuvwxyz");

        // Make sure minimum secret length can be undone correctly.
        secretMasker.MinimumSecretLength = 0;
        Assert.AreEqual(0, secretMasker.MinimumSecretLength);
        result = secretMasker.MaskSecrets(input);
        result.Should().Be("+++fg***lmno***stuvw***z");
    }

    [TestMethod]
    public async Task SecretMasker_MinimumSecretLengthInParallel()
    {
        var random = new Random();
        var secretMasker = new SecretMasker();
        secretMasker.AddValue("a");
        secretMasker.AddValue("de");
        secretMasker.AddRegex(new("", "", "", 0, pattern: "hij"));

        string testInput = "abcdefghij";
        HashSet<string> expectedResults = [
            "abcdefghij",     // MinimumSecretLength == 4
            "abcdefg+++",     // MinimumSecretLength == 3
            "abc***fg+++",    // MinimumSecretLength == 2
            "***bc***fg+++",  // MinimumSecretLength == 1
        ];

        var task = Task.Run(() =>
        {
            for (int i = 0; i < 100; i++)
            {
                string result = secretMasker.MaskSecrets(testInput);
                Assert.IsTrue(expectedResults.Contains(result),
                         $"""
                          {result} is not one of the expected results. 
                          Ensure that MinimumSecretLength is not read more than once per operation.
                          """);
            }
        });

        // Hammer MinimumSecretLength while the above task is running.
        while (!task.IsCompleted)
        {
            secretMasker.MinimumSecretLength = random.Next(1, 5);
        }

        await task;
    }

    [TestMethod]
    public void SecretMasker_NegativeMinimumSecretLengthSet()
    {
        using var secretMasker = new SecretMasker() { MinimumSecretLength = -3 };
        secretMasker.AddValue("efg");
        secretMasker.AddValue("bcd");

        string input = "abcdefgh";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("a***h", result);
    }

    [TestMethod]
    public void SecretMasker_NotAddShortEncodedSecrets()
    {
        string redactionToken = "qqq";
        using var secretMasker = new SecretMasker(regexSecrets: null, defaultLiteralRedactionToken: redactionToken);
        secretMasker.AddLiteralEncoder(new LiteralEncoder(x => x.Replace("123", "ab")));
        secretMasker.AddValue("123");
        secretMasker.AddValue("345");
        secretMasker.AddLiteralEncoder(new LiteralEncoder(x => x.Replace("345", "cd")));

        string input = "ab123cd345";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual(redactionToken, result);
    }

    [TestMethod]
    public void SecretMasker_NullEmptyAndWhiteSpaceRedactionTokensAreIgnored()
    {
        foreach (string token in new[] { string.Empty, null, " " })
        {
            using var secretMasker = new SecretMasker(defaultLiteralRedactionToken: token, defaultRegexRedactionToken: token);
            secretMasker.AddValue("abc");
            secretMasker.AddRegex(new RegexPattern(id: "123", name: "Name", "a test secret", DetectionMetadata.None, pattern: "def"));

            // There must be a space between the two matches to avoid coalescing
            // both finds into a single redaction operation.
            string input = "abc def";
            string result = secretMasker.MaskSecrets(input);

            Assert.AreEqual($"{SecretLiteral.FallbackRedactionToken} {RegexPattern.FallbackRedactionToken}", result);
        }
    }

    [TestMethod]
    public void SecretMasker_DistinguishLiteralAndRegexRedactionTokens()
    {
        using var secretMasker = new SecretMasker(defaultRegexRedactionToken: "zzz", defaultLiteralRedactionToken: "yyy") { MinimumSecretLength = 3 };

        secretMasker.AddRegex(new RegexPattern(id: "1000", name: "Name", "a test secret", DetectionMetadata.None, pattern: "abc"));
        secretMasker.AddValue("123");

        string input = "abcx123ab12";
        string result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("zzzxyyyab12", result);
    }

    [TestMethod]
    public void SecretMasker_ProvidesDetectionsViaCallback()
    {
        using var secretMasker = new SecretMasker(generateCorrelatingIds: true);
        secretMasker.AddRegex(new RegexPattern(id: "TEST000/001", name: "Pattern1", label: "", DetectionMetadata.None, pattern: "pattern1"));
        secretMasker.AddRegex(new RegexPattern(id: "TEST000/002", name: "Pattern2", label: "", DetectionMetadata.HighEntropy, pattern: "pattern2"));
        secretMasker.AddValue("literal1");

        string input = "yada yada pattern1 pattern2 literal1 yada yada";
        var detections = new List<Detection>();
        string result = secretMasker.MaskSecrets(input, d => detections.Add(d));

        Assert.AreEqual("yada yada +++ TEST000/002:UVpc+Yj5lkP42Qt1TT9Y *** yada yada", result); ;

        Assert.AreEqual(3, detections.Count);

        Assert.AreEqual("TEST000/001", detections[0].Id);
        Assert.AreEqual(input.IndexOf("pattern1"), detections[0].Start);
        Assert.AreEqual("pattern1".Length, detections[0].Length);

        Assert.AreEqual("TEST000/002", detections[1].Id);
        Assert.AreEqual(input.IndexOf("pattern2"), detections[1].Start);
        Assert.AreEqual("pattern2".Length, detections[1].Length);

        Assert.AreEqual(null, detections[2].Id);
        Assert.AreEqual(input.IndexOf("literal1"), detections[2].Start);
        Assert.AreEqual("literal1".Length, detections[2].Length);
    }

    [TestMethod]
    public void SecretMasker_ProvidesOverlappingAndAdjacentDetectionsViaCallbackButSkipsDuplicates()
    {
        using var secretMasker = new SecretMasker([]);

        string input = "The quick brown fox jumps over the lazy dog.";

        string[] values = [
            // Partially overlapping.
            "lazy dog",
            "y dog.",
            // Nested.
            "fox jumps",
            "jumps",
            // Same start position, different length.
            "over",
            "over the",
            // Adjacent.
            "quick",
            " brown",
        ];

        foreach (string value in values)
        {
            secretMasker.AddValue(value);

            // These will all be duplicates because they have the same start and
            // end and literal matches are preferred over regex matches.
            secretMasker.AddRegex(new("", "", "", 0, pattern: value));
        }

        // NOTE: DetectSecrets returns all detections in unspecified order.
        // while MaskSecrets invokes callback in documented order and excludes
        // duplicates with same start and end position.
        var maskedSecrets = new List<Detection>();
        var detectedSecrets = secretMasker.DetectSecrets(input).OrderBy(x => x.Start).ToList();
        string masked = secretMasker.MaskSecrets(input, maskedSecrets.Add);

        masked.Should().Be("The *** *** *** ***", masked);
        maskedSecrets.Should().HaveCount(8);

        // There should be twice as many results from DetectSecrets because
        // there's a duplicate regex match for each value match.
        detectedSecrets.Should().HaveCount(16);

        // If we take all the results of DetectSecrets, filter to only the
        // literal matches (regex matches are duplicates) we should get the same
        // results as MaskSecrets (in unspecified order).
        maskedSecrets.Should().BeEquivalentTo(detectedSecrets.Where(d => d.Kind == DetectionKind.Literal));

        maskedSecrets.Select(s => input.Substring(s.Start, s.Length))
                     .Should().BeEquivalentTo(["quick", " brown", "fox jumps", "jumps", "over the", "over", "lazy dog", "y dog."],
                                              o => o.WithStrictOrdering());
    }

    [TestMethod]
    public void SecretMasker_PrefersLiteralMatchesOverRegexMatches()
    {
        // Ensure that literal is preferred no matter how the redaction tokens sort.
        foreach ((string literalToken, string regexToken) in new[] { ("A", "B"), ("B", "A") })
        {
            var masker = new SecretMasker(defaultLiteralRedactionToken: literalToken, defaultRegexRedactionToken: regexToken);
            masker.AddValue("value");
            masker.AddRegex(new("", "", "", 0, "value"));
            string masked = masker.MaskSecrets("This has a value that also matches a regex");
            masked.Should().Be($"This has a {literalToken} that also matches a regex", because: $"literalToken={literalToken}");
        }
    }

    [TestMethod]
    public void SecretMasker_DetectionRepresentingDuplicateDoesNotDependOnC3ID()
    {
        var r1 = new RegexPattern("ID1", "", "", DetectionMetadata.HighEntropy, "mask");
        var r2 = new RegexPattern("ID2", "", "", DetectionMetadata.HighEntropy, "mask");
        var r3 = new RegexPattern("ID3", "", "", DetectionMetadata.HighEntropy, "mask");

        foreach (bool generateCorrelatingIds in new[] { false, true })
        {
            var detections = new List<Detection>();
            var masker = new SecretMasker([r3, r2, r1], generateCorrelatingIds: generateCorrelatingIds);
            string masked = masker.MaskSecrets("Please mask this", detections.Add);

            string redactionToken = generateCorrelatingIds ? "ID1:Sen+1PEeyyaiGi88hAdz" : "+++";
            string expected = $"Please {redactionToken} this";
            masked.Should().Be(expected);
            detections.Should().HaveCount(1, because: "the others are treated as duplicate.");
            detections[0].Id.Should().Be("ID1", because: "'ID1' sorts first");
        }
    }

    [TestMethod]
    public void SecretMasker_SortsDetectionsForMaskingInCorrectOrder()
    {
        var d1 = new Detection(id: "A", "", "", start: 0, length: 6, 0, redactionToken: "a", kind: DetectionKind.Literal);
        var d2 = new Detection(id: "A", "", "", start: 0, length: 5, 0, redactionToken: "a", kind: DetectionKind.Literal);
        var d3 = new Detection(id: "A", "", "", start: 0, length: 5, 0, redactionToken: "b", kind: DetectionKind.Literal);
        var d4 = new Detection(id: "B", "", "", start: 0, length: 5, 0, redactionToken: "a", kind: DetectionKind.Literal);
        var d5 = new Detection(id: "A", "", "", start: 0, length: 5, 0, redactionToken: "a", kind: DetectionKind.Regex);
        var d6 = new Detection(id: "A", "", "", start: 1, length: 5, 0, redactionToken: "a", kind: DetectionKind.Literal);

        // Start with reverse order.
        List<Detection> detections = [d6, d5, d4, d3, d2, d1];

        // Sort and expect sorted order.
        List<Detection> sorted = [d1, d2, d3, d4, d5, d6];
        SecretMasker.SortDetectionsForMasking(detections);
        detections.Should().BeEquivalentTo(sorted, o => o.WithStrictOrdering());

#if NET
        // Also test with randomly shuffled order when shuffle API is available.
        int seed = unchecked((int)DateTime.Now.Ticks);
        var random = new Random(seed);

        random.Shuffle(CollectionsMarshal.AsSpan(detections));
        SecretMasker.SortDetectionsForMasking(detections);
        detections.Should().BeEquivalentTo(sorted,
                                           o => o.WithStrictOrdering(),
                                           because: $"we shuffled using random seed={seed} and then sorted");
#endif
    }

    private enum SecretMaskerOperation
    {
        AddValue,
        AddLiteralEncoder,
        AddRegex,
        DetectSecrets,
        MaskSecrets,
    }

    private const int MaxSecretMaskerOperation = (int)SecretMaskerOperation.MaskSecrets;

    [TestMethod]
    public void SecretMasker_BasicThreadingStress()
    {
        int threadCount = Math.Min(4, Environment.ProcessorCount / 2);
        const int operationsPerThread = 200;

        using var secretMasker = new SecretMasker();

        // The values/encoders/regexes added on other threads won't impact this
        // test case. Note that we can't assert masking or detection results
        // based on the values/encoders/regexes added in parallel since they are
        // added randomly in between maksing and detection operations. It
        // stresses overlapping and non-overlapping code paths through mask
        // secrets.
        const string testInput = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt";
        secretMasker.AddValue("Lorem");
        secretMasker.AddValue("Lorem ipsum");
        secretMasker.AddValue("elit");
        string expectedOutput = testInput.Replace("Lorem ipsum", "***").Replace("elit", "***");
        string[] expectedSecrets = ["Lorem", "Lorem ipsum", "elit"];

        // Add values/encoders/regexes while masking and detecting secrets in
        // parallel. Generally any incorrect synchronization of the masker state
        // will manifest as an exception attempting to modify a collection while
        // enumerating it.
        var threads = new List<Thread>();
        using var startBarrier = new Barrier(threadCount + 1);
        var exceptions = new ConcurrentBag<Exception>();

        for (int t = 0; t < threadCount; t++)
        {
            int threadId = t;
            var thread = new Thread(() =>
            {
                try
                {
                    // Wait for all threads to be ready.
                    startBarrier.SignalAndWait();

                    var random = new Random();
                    for (int i = 0; i < operationsPerThread; i++)
                    {
                        int index = i;
                        var operation = (SecretMaskerOperation)random.Next(MaxSecretMaskerOperation + 1);
                        switch (operation)
                        {
                            case SecretMaskerOperation.AddValue:
                            {
                                secretMasker.AddValue($"{threadId}_value_{index}");
                                secretMasker.AddValue("some constant value");
                                break;
                            }

                            case SecretMaskerOperation.AddLiteralEncoder:
                            {
                                secretMasker.AddLiteralEncoder(v => $"{threadId}_{v}_encoder_{index}");
                                secretMasker.AddLiteralEncoder(WellKnownLiteralEncoders.UnescapeBackslashes);
                                break;
                            }

                            case SecretMaskerOperation.AddRegex:
                            {
                                secretMasker.AddRegex(new(id: $"{threadId}_id_{index}",
                                                      name: $"{threadId}_name_{index}",
                                                      label: $"{threadId}_label_{index}",
                                                      patternMetadata: DetectionMetadata.None,
                                                      pattern: $"{threadId}_pattern_{index}"));

                                IReadOnlyList<RegexPattern> patterns = WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys;
                                secretMasker.AddRegex(patterns[random.Next(patterns.Count)]);
                                break;
                            }

                            case SecretMaskerOperation.DetectSecrets:
                            {
                                IEnumerable<Detection> detections = secretMasker.DetectSecrets(testInput);
                                var secrets = detections.Select(d => testInput.Substring(d.Start, d.Length)).ToList();
                                CollectionAssert.AreEquivalent(expectedSecrets, secrets);
                                break;
                            }

                            case SecretMaskerOperation.MaskSecrets:
                            {
                                string masked = secretMasker.MaskSecrets(testInput);
                                Assert.AreEqual(expectedOutput, masked);
                                break;
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    exceptions.Add(ex);
                }
            });

            threads.Add(thread);
            thread.Start();
        }

        // Signal threads to start
        startBarrier.SignalAndWait();

        // Wait for all threads to complete
        foreach (Thread thread in threads)
        {
            thread.Join();
        }

        if (exceptions.Count > 0)
        {
            throw new AggregateException("One or more exceptions occurred during the threading stress test", exceptions);
        }
    }

    [DataTestMethod]
    [DataRow("ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA==", "SEC101/158:R6+pDaPrTyjBTsNUJ6dj")]
    [DataRow("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee+ACRCTB7t/", "SEC101/176:aL4C/u4qSVE6uQCXPICc")]
    [DataRow("oy2mdeaddeaddeadeadqdeaddeadxxxezodeaddeadwxuq", "SEC101/031:G47Z8IeLmqos+/TXkWoH")]
    [DataRow("npm_deaddeaddeaddeaddeaddeaddeaddeaddead", "SEC101/050:bUOMn/+Dx0jUK71D+nHu")]
    [DataRow("xxx8Q~dead.dead.DEAD-DEAD-dead~deadxxxxx", "SEC101/156:vcocI2kI5E2ycoG55kza")]
    [DataRow("xxx7Q~dead.dead.DEAD-DEAD-dead~deadxx", "SEC101/156:WNRIG2TMMQjdUEGSNRIQ")]
    public void SecretMasker_PlaceholderTestSecretsAreMasked(string input, string expected)
    {
        string expectedC3Id = expected.Substring(expected.IndexOf(':') + 1);
        Assert.AreEqual(expectedC3Id, RegexPattern.GenerateCrossCompanyCorrelatingId(input));

        using var secretMasker = new SecretMasker(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys, generateCorrelatingIds: true);
        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(expected, actual);
    }

    [DataTestMethod]
    [DataRow("SSdtIGEgY29tcGxldGVseSBpbm5vY3VvdXMgc3RyaW5nLg==")]
    [DataRow("The password is knock knock knock")]
    public void SecretMasker_FalsePositiveValuesAreNotMasked(string input)
    {
        using var secretMasker = new SecretMasker(WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels);
        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(input, actual);
    }

    private static void ValidateTelemetry(SecretMasker testSecretMasker)
    {
        Assert.IsTrue(testSecretMasker.ElapsedMaskingTime.Ticks > 0);
    }
}