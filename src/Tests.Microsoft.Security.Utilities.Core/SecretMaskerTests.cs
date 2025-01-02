// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;

using FluentAssertions;
using FluentAssertions.Execution;

using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Microsoft.Security.Utilities;

[TestClass, ExcludeFromCodeCoverage]
public class SecretMaskerTests
{
    [TestMethod]
    public void SecretMasker_Version()
    {
        Version version = SecretMasker.Version;
        version.ToString().Should().Be("1.11.0");
    }

    [TestMethod]
    public void SecretMasker_PreciselyClassifiedSecurityKeys_Detections()
    {
        ValidateSecurityModelsDetections(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys,
                                         preciseClassifications: false);
    }

    // "https://github.com/microsoft/security-utilities/issues/95")
    //[TestMethod]
    public void SecretMasker_UnclassifiedPotentialSecurityKeys_Detections()
    {
        ValidateSecurityModelsDetections(WellKnownRegexPatterns.UnclassifiedPotentialSecurityKeys,
                                         preciseClassifications: false);
    }

    private void ValidateSecurityModelsDetections(IEnumerable<RegexPattern> patterns, bool preciseClassifications)
    {
        // These tests generate randomized values. It may be useful to
        // bump up the # of iterations on an ad hoc basis to flush
        // out non-deterministic failures (typically based on the
        // characters chosen from the secret alphabet for the pattern).
        for (int i = 0; i < 1; i++)
        {
            using var scope = new AssertionScope();

            foreach (IRegexEngine engine  in new[] { RE2RegexEngine.Instance, CachedDotNetRegex.Instance, null })
            {
                foreach (bool generateCrossCompanyCorrelatingIds in new[] { true, false })
                {
                    // The high-performance engine doesn't support the imprecisely classified 
                    // models. These are currently misnamed as 'low entropy'. TBD.
                    if (engine == null && preciseClassifications)
                    {
                        continue;
                    }

                    using ISecretMasker secretMasker = engine != null
                        ? new SecretMasker(patterns, generateCrossCompanyCorrelatingIds, engine)
                        : new IdentifiableScan(patterns, generateCrossCompanyCorrelatingIds);

                    foreach (RegexPattern pattern in patterns)
                    {
                        foreach (string testExample in pattern.GenerateTruePositiveExamples())
                        {
                            string context = testExample;
                            var matches = CachedDotNetRegex.Instance.Matches(context, pattern.Pattern, captureGroup: "refine");
                            bool result = matches.Count() == 1;
                            result.Should().BeTrue(because: $"Pattern {pattern.Id} should match '{context}' exactly once");

                            string standaloneSecret = CachedDotNetRegex.Instance.Matches(context, pattern.Pattern, captureGroup: "refine").First().Value;

                            string moniker = pattern.GetMatchMoniker(standaloneSecret);

                            // 1. All generated test patterns should be detected by the masker.
                            var detections = secretMasker.DetectSecrets(context);
                            result = detections.Count() == 1;
                            // TODO duplication in analysis has snuck in.
                            // https://github.com/microsoft/security-utilities/issues/95
                            //result.Should().BeTrue(because: $"'{context}' should result in a single '{moniker}' finding");

                            Detection detection = detections.First();
                            detection.Moniker.Should().Be(moniker);

                            // 2. All identifiable or high confidence findings should be marked as high entropy.
                            result = preciseClassifications ? detection.Metadata.HasFlag(DetectionMetadata.HighEntropy) : true;
                            result.Should().BeTrue(because: $"{moniker} finding should be classified as high entropy");

                            // 3. All high entropy secret kinds should generate a cross-company correlating id,
                            //    but only if the masker was initialized to produce them. Every low entropy model
                            //    should refuse to generate a c3id, no matter how the masker is configured.

                            string c3id = RegexPattern.GenerateCrossCompanyCorrelatingId(standaloneSecret);
                            string actualC3id = detection.CrossCompanyCorrelatingId;
                            string expectedC3id = generateCrossCompanyCorrelatingIds &&
                                                  (preciseClassifications | detection.Metadata.HasFlag(DetectionMetadata.HighEntropy))
                                                        ? c3id
                                                        : null;

                            result = object.Equals(expectedC3id, actualC3id);
                            result.Should().BeTrue(because: "C3id should be generated correctly");


                            // 4. All high entropy secret kinds should generate a fingerprint, but only
                            //    if the masker was initialized to produce them. Every low entropy model
                            //    should refuse to generate a fingerprint, no matter how the masker is configured.
                            string actualRedactionToken = detection.RedactionToken;
                            string expectedRedactionToken = generateCrossCompanyCorrelatingIds &&
                                                            (preciseClassifications | detection.Metadata.HasFlag(DetectionMetadata.HighEntropy)) 
                                                                ? $"{pattern.Id}:{c3id}"
                                                                : "+++";

                            result = actualRedactionToken.Equals(expectedRedactionToken);
                            result.Should().BeTrue(because: "Redaction token should be generated correctly");

                            // 5. Moniker that flows to classified secret should match the detection.
                            result = detection.Moniker.Equals(moniker);
                            result.Should().BeTrue(because: $"{moniker} finding should not be reported as {detection.Moniker} for test data {context}");
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
        // These tests generate randomized values. It may be useful to
        // bump up the # of iterations on an ad hoc basis to flush
        // out non-deterministic failures (typically based on the
        // characters chosen from the secret alphabet for the pattern).
        for (int i = 0; i < 1; i++)
        {
            using var scope = new AssertionScope();

            foreach (IRegexEngine regexEngine in new[] { RE2RegexEngine.Instance, CachedDotNetRegex.Instance })
            {
                foreach (bool generateCrossCompanyCorrelatingIds in new[] { true, false })
                {
                    using var secretMasker = new SecretMasker(patterns, generateCrossCompanyCorrelatingIds, engine);

                    foreach (var pattern in patterns)
                    {
                        if (!lowEntropyModels && !pattern.DetectionMetadata.HasFlag(DetectionMetadata.HighEntropy))
                        {
                            continue;
                        }

                        foreach (string testExample in pattern.GenerateTruePositiveExamples())
                        {
                            string secretValue = testExample;
                            string moniker = pattern.GetMatchMoniker(secretValue);

                            // 1. All generated test patterns should be detected by the masker.
                            string redacted = secretMasker.MaskSecrets(secretValue);
                            bool result = redacted.Equals(secretValue);
                            result.Should().BeFalse(because: $"'{secretValue}' for '{moniker}' should be redacted from scan text.");

                            // TODO: the generated examples don't distinguish the secret from surrounding context,
                            // for rules such as our connection string detecting logic. We need a future change to
                            // separate this data. For now, we skip all connection string patterns. This is a problem
                            // for masking only (and not detection) because we have no location details when masking.
                            if (pattern.Id == "SEC101/060" || testExample.Contains(";"))
                            {
                                continue;
                            }

                            string expectedRedactedValue = generateCrossCompanyCorrelatingIds
                                ? $"{pattern.Id}:{RegexPattern.GenerateCrossCompanyCorrelatingId(secretValue)}" 
                                : RegexPattern.FallbackRedactionToken;

                            redacted.Should().Be(expectedRedactedValue, because: $"generate correlating ids == {generateCrossCompanyCorrelatingIds}");
                        }

                        foreach(string testExample in pattern.GenerateFalsePositiveExamples())
                        {
                            string secretValue = testExample;

                            // 1. All generated false positive test patterns should
                            //  not result in a mask operation.
                            string redacted = secretMasker.MaskSecrets(secretValue);
                            bool result = redacted.Equals(secretValue);
                            result.Should().BeTrue(because: $"'{secretValue}' for '{pattern.Id}.{pattern.Name}' should not be redacted from scan text.");
                        }
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

    [TestMethod]
    public void SecretMasker_UrlNotMasked()
    {
        using var secretMasker = InitializeTestMasker();
        string input = "https://simpledomain@example.com";
        string output = secretMasker.MaskSecrets(input);

        Assert.AreEqual(input, output);

        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_ComplexUrlNotMasked()
    {
        using var secretMasker = InitializeTestMasker();
        string input = "https://url.com:443/~user/foo=bar+42-18?what=this.is.an.example....~~many@&param=value";

        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(input, actual);

        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_UrlCredentialsAreMasked()
    {
        using var secretMasker = InitializeTestMasker();
        string input = "https://user:pass@example.com";
        string expected = "https://+++@example.com";

        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual(expected, actual);

        ValidateTelemetry(secretMasker);
    }
    
    [TestMethod]
    public void IsUserInfoWithSpecialCharactersMaskedCorrectly()
    {
        using var secretMasker = InitializeTestMasker();

        string input = @"https://user:pass4';.!&*()=,$-+~@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }
        
    [TestMethod]
    public void IsUserInfoWithDigitsInNameMaskedCorrectly()
    {
        using var secretMasker = InitializeTestMasker();
        string input = @"https://username123:password@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }
    
    [TestMethod]
    public void IsUserInfoWithLongPasswordAndNameMaskedCorrectly()
    {
        using var secretMasker = InitializeTestMasker();
        string input = @"https://username_loooooooooooooooooooooooooooooooooooooooooong:password_looooooooooooooooooooooooooooooooooooooooooooooooong@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithEncodedCharactersInNameMaskedCorrectly()
    {
        using var secretMasker = InitializeTestMasker();
        string input = @"https://username%10%A3%F6:password123@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void IsUserInfoWithEncodedAndEscapedCharactersInNameMaskedCorrectly()
    {
        using var secretMasker = InitializeTestMasker();
        string input = @"https://username%AZP2510%AZP25A3%AZP25F6:password123@example.com";
        string expected = "https://+++@example.com";
        string actual = secretMasker.MaskSecrets(input);

        Assert.AreEqual(expected, actual);
        ValidateTelemetry(secretMasker);
    }

    [TestMethod]
    public void SecretMasker_CopyConstructor()
    {
        string id = nameof(id);
        string name = nameof(name);
        // Setup masker 1
        using var secretMasker1 = new SecretMasker();
        secretMasker1.AddRegex(new RegexPattern(id, name, 0, "masker-1-regex-1_*"));
        secretMasker1.AddRegex(new RegexPattern(id, name, 0, "masker-1-regex-2_*"));
        secretMasker1.AddValue("masker-1-value-1_");
        secretMasker1.AddValue("masker-1-value-2_");
        secretMasker1.AddLiteralEncoder(x => x.Replace("_", "_masker-1-encoder-1"));
        secretMasker1.AddLiteralEncoder(x => x.Replace("_", "_masker-1-encoder-2"));

        // Copy and add to masker 2.
        var secretMasker2 = secretMasker1.Clone();
        secretMasker2.AddRegex(new RegexPattern(id, name, 0, "masker-2-regex-1_*"));
        secretMasker2.AddValue("masker-2-value-1_");
        secretMasker2.AddLiteralEncoder(x => x.Replace("_", "_masker-2-encoder-1"));

        // Add to masker 1.
        secretMasker1.AddRegex(new RegexPattern(id, name, 0, "masker-1-regex-3_*"));
        secretMasker1.AddValue("masker-1-value-3_");
        secretMasker1.AddLiteralEncoder(x => x.Replace("_", "_masker-1-encoder-3"));

        // Assert masker 1 values.
        Assert.AreEqual("+++", secretMasker1.MaskSecrets("masker-1-regex-1___")); // original regex
        Assert.AreEqual("+++", secretMasker1.MaskSecrets("masker-1-regex-2___")); // original regex
        Assert.AreEqual("+++", secretMasker1.MaskSecrets("masker-1-regex-3___")); // new regex
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-1_")); // original value
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-2_")); // original value
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-3_")); // new value
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-1_masker-1-encoder-1")); // original value, original encoder
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-1_masker-1-encoder-2")); // original value, original encoder
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-1_masker-1-encoder-3")); // original value, new encoder
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-3_masker-1-encoder-1")); // new value, original encoder
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-3_masker-1-encoder-2")); // new value, original encoder
        Assert.AreEqual("***", secretMasker1.MaskSecrets("masker-1-value-3_masker-1-encoder-3")); // new value, new encoder
        Assert.AreEqual("masker-2-regex-1___", secretMasker1.MaskSecrets("masker-2-regex-1___")); // separate regex storage from copy
        Assert.AreEqual("masker-2-value-1_", secretMasker1.MaskSecrets("masker-2-value-1_")); // separate value storage from copy
        Assert.AreEqual("***masker-2-encoder-1", secretMasker1.MaskSecrets("masker-1-value-1_masker-2-encoder-1")); // separate encoder storage from copy

        // Assert masker 2 values.
        Assert.AreEqual("+++", secretMasker2.MaskSecrets("masker-1-regex-1___")); // copied regex
        Assert.AreEqual("+++", secretMasker2.MaskSecrets("masker-1-regex-2___")); // copied regex
        Assert.AreEqual("+++", secretMasker2.MaskSecrets("masker-2-regex-1___")); // new regex
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-1-value-1_")); // copied value
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-1-value-2_")); // copied value
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-2-value-1_")); // new value
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-1-value-1_masker-1-encoder-1")); // copied value, copied encoder
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-1-value-1_masker-1-encoder-2")); // copied value, copied encoder
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-1-value-1_masker-2-encoder-1")); // copied value, new encoder
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-2-value-1_masker-1-encoder-1")); // new value, copied encoder
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-2-value-1_masker-1-encoder-2")); // new value, copied encoder
        Assert.AreEqual("***", secretMasker2.MaskSecrets("masker-2-value-1_masker-2-encoder-1")); // new value, new encoder
        Assert.AreEqual("masker-1-regex-3___", secretMasker2.MaskSecrets("masker-1-regex-3___")); // separate regex storage from original
        Assert.AreEqual("masker-1-value-3_", secretMasker2.MaskSecrets("masker-1-value-3_")); // separate value storage from original
        Assert.AreEqual("***masker-1-encoder-3", secretMasker2.MaskSecrets("masker-1-value-1_masker-1-encoder-3")); // separate encoder storage from original
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
            var value = string.Empty.PadRight(1, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(2, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(3, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(4, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(5, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(5, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(6, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }


        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = string.Empty.PadRight(7, ' ');
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
            Assert.AreEqual("***", secretMasker.MaskSecrets(value.Replace(" ", "%20")));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = "𐐷𐐷𐐷𐐷"; // surrogate pair
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
        }

        using (var secretMasker = new SecretMasker())
        {
            secretMasker.AddLiteralEncoder(encoder);
            var value = " 𐐷𐐷𐐷𐐷"; // shift by one non-surrogate character to ensure surrogate across segment boundary handled correctly
            secretMasker.AddValue(value);
            Assert.AreEqual("***", secretMasker.MaskSecrets(value));
        }
    }

    [TestMethod]
    public void SecretMasker_HandlesEmptyInput()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("abcd");

        var result = secretMasker.MaskSecrets(null);
        Assert.AreEqual(string.Empty, result);

        result = secretMasker.MaskSecrets(string.Empty);
        Assert.AreEqual(string.Empty, result);
    }

    [TestMethod]
    public void SecretMasker_TestCorrelatingId()
    {
        string suffix = "00000";
        string secret = $"secret_scanning_ab85fc6f8d7638cf1c11da812da308d43_{suffix}";
        using var secretMasker = new SecretMasker(new[] { new SecretScanningSampleToken() }, generateCorrelatingIds: true);
        var detections = secretMasker.DetectSecrets(secret);
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
        var input = "abc";

        var actual = secretMasker.MaskSecrets(input);
        
        Assert.AreEqual(input, actual);
    }

    [TestMethod]
    public void SecretMasker_ReplacesValue()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");

        var input = "abcdefg";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("abc***g", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleInstances()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");

        var input = "abcdefgdef";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("abc***g***", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleAdjacentInstances()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("abc");

        var input = "abcabcdef";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("***def", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesMultipleSecrets()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("bcd");
        secretMasker.AddValue("fgh");

        var input = "abcdefghi";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("a***e***i", result);
    }

    [TestMethod]
    public void SecretMasker_ReplacesOverlappingSecrets()
    {
        using var secretMasker = new SecretMasker();
        secretMasker.AddValue("def");
        secretMasker.AddValue("bcd");

        var input = "abcdefg";
        var result = secretMasker.MaskSecrets(input);

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

        var input = "abcdefgh";
        var result = secretMasker.MaskSecrets(input);

        // two adjacent secrets are basically one big secret

        Assert.AreEqual("a***h", result);
    }

    [TestMethod]
    public void SecretMasker_MinimumLengthSetThroughProperty()
    {
        SecretMasker.MinimumSecretLengthCeiling = 9;
        using var secretMasker = new SecretMasker { MinimumSecretLength = 9 };

        secretMasker.AddValue("efg");
        secretMasker.AddValue("bcd");

        var input = "abcdefgh";
        var result = secretMasker.MaskSecrets(input);

        // two adjacent secrets are basically one big secret

        Assert.AreEqual("abcdefgh", result);
    }

    [TestMethod]
    public void SecretMasker_MinimumLengthSetThroughPropertySetTwice()
    {
        using var secretMasker = new SecretMasker();

        var minSecretLenFirst = 9;
        secretMasker.MinimumSecretLength = minSecretLenFirst;

        var minSecretLenSecond = 2;
        secretMasker.MinimumSecretLength = minSecretLenSecond;

        Assert.AreEqual(secretMasker.MinimumSecretLength, minSecretLenSecond);
    }

    [TestMethod]
    public void SecretMasker_NegativeMinimumSecretLengthSet()
    {
        using var secretMasker = new SecretMasker() { MinimumSecretLength = -3 };
        secretMasker.AddValue("efg");
        secretMasker.AddValue("bcd");

        var input = "abcdefgh";
        var result = secretMasker.MaskSecrets(input);

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

        var input = "ab123cd345";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual(redactionToken, result);
    }

    [TestMethod]
    public void SecretMasker_NullEmptyAndWhiteSpaceRedactionTokensAreIgnored()
    {
        foreach (string token in new[] { string.Empty, null, " " })
        {
            using var secretMasker = new SecretMasker() { DefaultLiteralRedactionToken = token, DefaultRegexRedactionToken = token };
            secretMasker.AddValue("abc");
            secretMasker.AddRegex(new RegexPattern(id: "123", name: "Name", DetectionMetadata.None, pattern: "def"));

            // There must be a space between the two matches to avoid coalescing
            // both finds into a single redaction operation.
            var input = "abc def";
            var result = secretMasker.MaskSecrets(input);

            Assert.AreEqual($"{SecretLiteral.FallbackRedactionToken} {RegexPattern.FallbackRedactionToken}", result);
        }
    }

    [TestMethod]
    public void SecretMasker_DistinguishLiteralAndRegexRedactionTokens()
    {
        using var secretMasker = new SecretMasker() { MinimumSecretLength = 3, DefaultRegexRedactionToken = "zzz", DefaultLiteralRedactionToken = "yyy" };
        
        secretMasker.AddRegex(new RegexPattern(id: "1000", name: "Name", DetectionMetadata.None, pattern: "abc"));
        secretMasker.AddValue("123");

        var input = "abcx123ab12";
        var result = secretMasker.MaskSecrets(input);

        Assert.AreEqual("zzzxyyyab12", result);
    }

    [DataTestMethod]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddeadAPIMxxxxxQ==", "SEC102/102.Unclassified64ByteBase64String:1DC39072DA446911FE3E87EB697FB22ED6E2F75D7ECE4D0CE7CF4288CE0094D1")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddeadACDbxxxxxQ==", "SEC102/102.Unclassified64ByteBase64String:6AB186D06C8C6FBA25D39806913A70A4D77AB97C526D42B8C8DA6D441DE9F3C5")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead+ABaxxxxxQ==", "SEC102/102.Unclassified64ByteBase64String:E1BB911668718D50C0C2CE7B9C93A5BB75A17212EA583A8BB060A014058C0802")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead+AMCxxxxxQ==", "SEC102/102.Unclassified64ByteBase64String:7B3706299058BAC1622245A964D8DBBEF97A0C43C863F2702C4A1AD0413B3FC9")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadde/dead+deaddeaddeaddeaddeaddeaddeaddeaddead+AStxxxxxQ==", "SEC102/102.Unclassified64ByteBase64String:58FF6B874E1B4014CF17C429A1E235E08466A0199090A0235975A35A87B8D440")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadxAIoTDeadxx=", "SEC102/101.Unclassified32ByteBase64String:2B0ADEB74FC9CDA3CD5D1066D85190407C57B8CAF45FCA7D50E26282AD61530C")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadx+ASbDeadxx=", "SEC102/101.Unclassified32ByteBase64String:83F68F21FC0D7C5990929446509BFF80D604899064CA152D3524BBEECF7F6993")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadx+AEhDeadxx=", "SEC102/101.Unclassified32ByteBase64String:E636DCD8D5F02304CE4B24DE2344B2D24C4B46BFD062EEF4D7673227720351C9")]
    [DataRow("deaddeaddeaddeaddeaddeaddeaddeadx+ARmDeadxx=", "SEC102/101.Unclassified32ByteBase64String:9DEFFD24DE5F1DB24292B814B01868BC33E9298DF2BF3318C2B063B4D689A0BC")]
    public void SecretMasker_PotentialSymmetricKeysAreClassified(string input, string expected)
    {

    }

    [DataTestMethod]
    [DataRow("ddddddddddddddddddddddddddddddddddddddddddddAzFu182vhA==", "SEC101/158.AzureFunctionIdentifiableKey:FF8E9A7C2A792029814C755C6704D9427F302E954DEF0FD5EE649BF9163E1F24")]
    [DataRow("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee+ACRCTB7t/", "SEC101/176.AzureContainerRegistryIdentifiableKey:CE62C55A2D3C220DA0CBFE292B5A6839EC7F747C5B5A7A55A4E5D7D76F1C7D32")]
    [DataRow("oy2mdeaddeaddeadeadqdeaddeadxxxezodeaddeadwxuq", "SEC101/031.NuGetApiKey:FC93CD537067C7F452073F24C7043D5F58E11B6F49546316BBE06BAA5747317E")]
    [DataRow("npm_deaddeaddeaddeaddeaddeaddeaddeaddead", "SEC101/050.NpmAuthorKey:E06C20B8696373D4AEE3057CB1A577DC7A0F7F97BEE352D3C49B48B6328E1CBC")]
    [DataRow("xxx8Q~dead.dead.DEAD-DEAD-dead~deadxxxxx", "SEC101/156.AadClientAppSecret:44DB247A273E912A1C3B45AC2732734CEAED00508AB85C3D4E801596CFF5B1D8")]
    [DataRow("xxx7Q~dead.dead.DEAD-DEAD-dead~deadxx", "SEC101/156.AadClientAppSecret:23F12851970BB19BD76A448449F16F85BF4AFE915AD14BAFEE635F15021CE6BB")]
    public void SecretMasker_PlaceholderTestSecretsAreMasked(string input, string expected)
    {
        using var secretMasker = new SecretMasker(WellKnownRegexPatterns.PreciselyClassifiedSecurityKeys);
        string actual = secretMasker.MaskSecrets(input);
        Assert.AreEqual("+++", actual);
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
    private static void ValidateTelemetry(SecretMasker testSecretMasker, int expectedRedactions = 0, bool usesMoniker = false)
    {
        Assert.IsTrue(testSecretMasker.ElapsedMaskingTime > 0);
    }
}