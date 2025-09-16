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
    public void HighPerformanceScanner_NoPatterns()
    {
        var scanner = new HighPerformanceScanner();
        List<HighPerformanceDetection> detections = scanner.Scan(input: "Hello");
        detections.Should().BeEmpty();
    }


    [TestMethod]
    public void HighPerformanceScanner_AdjacentMatches()
    {
        /* lang=regex */
        const string regexA = """^[A-Z]{4}AAAA[A-Z]{4}""";
        /* lang=regex */
        const string regexB = """^BBBB[A-Z]{4}""";

        CompiledHighPerformancePattern[] patterns = [
            new("AAAA", 4, 12, 12, new Regex(regexA)),
            new("BBBB", 0, 8, 8, new Regex(regexB)),
        ];

        string input = "_QQQQAAAAWWWWBBBBXXXX";

        HighPerformanceDetection[] expectedDetections = [
            new("AAAA", start: 1, length: 12),
            new("BBBB", start: 13, length: 8),
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);
        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_OverlappingMatches_OnlyFirstOneIsReturned()
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
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);
        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_OverlappingSignatures()
    {
        /* lang=regex */
        const string regexA = """^[0-9]{4}....[A-Z]{4}""";
        /* lang=regex */
        const string regexB = """^[A-Z]{4}....[A-Z]{4}""";

        CompiledHighPerformancePattern[] patterns = [
            new("AAAA", 4, 12, 12, new Regex(regexA)),
            new("AAAB", 4, 12, 12, new Regex(regexB)),
        ];
        

        // AAAA signature is found first, but regex doesn't match (expects
        // digits before signature). Overlapping AAAB signature is found next
        // and regex matches.
        string input = "QQQQAAAABJJJJ";

        HighPerformanceDetection[] expectedDetections = [
            new("AAAB", start: 1, length: 12),
        ];

        var scanner = new HighPerformanceScanner(patterns);
        List<HighPerformanceDetection> actualDetections = scanner.Scan(input);
        actualDetections.Should().BeEquivalentTo(expectedDetections);
    }

    [TestMethod]
    public void HighPerformanceScanner_EdgeCases()
    {
        /* lang=regex */
        const string regex = """^[A-Z]{4}.{4}[A-Z]{4}""";

        CompiledHighPerformancePattern[] patterns = [
            new("AAAA", 4, 12, 12, new Regex(regex)),
        ];

        // Code coverage:
        // - Non-ascii char in all four signature positions.
        // - Signature match at the end of the input.
        string input = "🙂 QQQQAAAABBBB éAAA AéAA AAéA AAAé AAAA";

        HighPerformanceDetection[] expectedDetections = [
            new("AAAA", start: input.IndexOf("QQQQ"), length: 12),
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
}
