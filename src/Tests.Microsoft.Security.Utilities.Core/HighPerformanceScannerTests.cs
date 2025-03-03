// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;
using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace Tests.Microsoft.Security.Utilities.Core;

[TestClass]
public class HighPerformanceScannerTests
{
    [TestMethod]
    public void HighPerformanceScanner_EmptyInput()
    {
        var scanner = new HighPerformanceScanner([CompiledHighPerformancePattern.ForSignature("JQQJ")]);
        List<HighPerformanceDetection> detections = scanner.Scan(input: string.Empty);
        detections.Should().BeEmpty();
    }

    [TestMethod]
    public void HighPerformanceScanner_OverlappingMatches()
    {
        /* lang=regex */
        const string regex = """^[A-Z]{4}....[A-Z]{4}""";

        CompiledHighPerformancePattern[] patterns = [
            new("AAAA", 4, 12, 12, new Regex(regex)),
            new("BBBB", 4, 12, 12, new Regex(regex)),
        ];

        string input = "QQQQAAAABBBBJJJJ";

        HighPerformanceDetection[] expectedDetections = [
            new("AAAA", start: 0, length: 12),
            new("BBBB", start: 4, length: 12),
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);
        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_InterestingSignatures()
    {
        /* lang=regex */
        const string regex3 = """^[A-Z]{4}.{3}[A-Z]{4}""";
        /* lang=regex */
        const string regex4 = """^[A-Z]{4}.{4}[A-Z]{4}""";

        // 3 and 4 char signature that overlap
        CompiledHighPerformancePattern[] patterns = [
            new("AAA",  4, 11, 11, new Regex(regex3)),
            new("AAAZ", 4, 12, 12, new Regex(regex4)),
        ];

        // Non-ascii char in all four signature positions.
        // Signature match at the end of the input.
        string input = "QQQQAAABBBB yada yada yada QQQQAAAZBBBB AAAW yada yada yada éAAA AéAA AAéA AAA";

        HighPerformanceDetection[] expectedDetections = [
            new("AAA", start: 0, length: 11),
            new("AAAZ", start: input.LastIndexOf("QQQQ"), length: 12),
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);

        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_WithAndWithoutOptionalEnding()
    {
        /* lang=regex */
        const string regex = """^[A-Z]{4}.{4}[A-Z]{4}([A-Z]{4})?""";
        CompiledHighPerformancePattern[] patterns = [
            new("QQQQ", signaturePrefixLength: 4, minMatchLength: 12, maxMatchLength: 16, new Regex(regex)),
        ];

        string input = "AAAAQQQQBBBB yada yada yada AAAAQQQQBBBBCCCC";

        HighPerformanceDetection[] expectedDetections = [
            new("QQQQ", start: 0, length: 12),
            new("QQQQ", start: input.LastIndexOf("AAAA"), length: 16)
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);

        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_TooShortToMatch()
    {
        /* lang=regex */
        const string regex = """^[A-Z]{4}.{4}[A-Z]{4}""";
        CompiledHighPerformancePattern[] patterns = [
            new("QQQQ", signaturePrefixLength: 4, minMatchLength: 12, maxMatchLength: 16, new Regex(regex)),
        ];
        string input = "AAAAQQQQBBB";

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> detections = scanner.Scan(input);

        detections.Should().BeEmpty();
    }

    [TestMethod]
    public void HighPerformanceScanner_SignatureTooEarlyToMatch()
    {
        /* lang=regex */
        const string regex = """^[A-Z]{4}.{4}[A-Z]{4}""";
        CompiledHighPerformancePattern[] patterns = [
            new("QQQQ", signaturePrefixLength: 4, minMatchLength: 12, maxMatchLength: 16, new Regex(regex)),
        ];
        string input = "QQQQBBBBCCCC yada yada yada";

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> detections = scanner.Scan(input);

        detections.Should().BeEmpty();
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_SharesRegexesOptimally()
    {
        // These two patterns differ only by signature.
        var pattern = CompiledHighPerformancePattern.ForSignature(IdentifiableMetadata.AzureIotSignature);
        var pattern2 = CompiledHighPerformancePattern.ForSignature(IdentifiableMetadata.AzureEventGridSignature);

        // This is a valid version of both of patterns except the signature is
        // all newlines. If the scoped regex doesn't match this, it has not been
        // configured optimally using 'RegexOptions.SingleLine'.
        string input = new string('A', 33) + new string('\n', 4) + new string('A', 6) + '=';

        pattern.ScopedRegex.Should().BeSameAs(pattern2.ScopedRegex, because: "these patterns differ only by signature and can share a scoped regex");
        pattern.ScopedRegex.IsMatch(input).Should().BeTrue(because: "the shared scoped regex should skip signature chars, even newlines");
    }
}
