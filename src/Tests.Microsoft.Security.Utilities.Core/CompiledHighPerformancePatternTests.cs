// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using FluentAssertions;
using Microsoft.Security.Utilities;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;

namespace Tests.Microsoft.Security.Utilities.Core;

[TestClass]
public class CompiledHighPerformancePatternTests
{
#if HIGH_PERFORMANCE_CODEGEN
    // TODO: Use Roslyn generator: https://github.com/microsoft/security-utilities/issues/152
    [TestMethod]
    public void CompiledHighPerformancePattern_EnsureCodeGenIsUpToDate()
    {
        string expected = CompiledHighPerformancePattern.GenerateAdditionalCode();
        string path = GetGeneratedFilePath();
        string actual = File.ReadAllText(path);

        // Use EndsWith because the file also has a comment at the top. Also,
        // ignore whitespace at the end of both sides.
        if (!actual.TrimEnd().EndsWith(expected.TrimEnd(), StringComparison.Ordinal))
        {
            Assert.Fail($"""
                        The generated code in '${path}' is out-of-date.
                        To regenerate:
                          - Open '{Path.ChangeExtension(path, ".tt")}' in Visual Studio
                          - Select Debug configuration.
                          - Hit Ctrl+S to save.
                        """);
        }
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsSharedSignatureWithDifferentPatterns()
    {
        for (int i = 0; i < 4; i++)
        {
            string regex = "^";
            int signaturePrefixLength = 1;
            int minMatchLength = 5;
            int maxMatchLength = 6;

            var pattern1 = new HighPerformancePattern("SIGN", regex, signaturePrefixLength, minMatchLength, maxMatchLength);

            switch (i)
            {
                case 0:
                    regex += "x";
                    break;
                case 1:
                    signaturePrefixLength++;
                    break;
                case 2:
                    minMatchLength++;
                    break;
                  case 3:
                    maxMatchLength++;
                    break;
            }

            var pattern2 = new HighPerformancePattern("SIGN", regex, signaturePrefixLength, minMatchLength, maxMatchLength);
            Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern1, pattern2]), $"Iteration: {i}.");
        }
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsShortSignatureThatIsPrefixOfLongerSignature()
    {
        var pattern1 = new HighPerformancePattern("SIG", "^", 1, 5, 6);
        var pattern2 = new HighPerformancePattern("SIGN", "^", 1, 5, 6);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern1, pattern2]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsRegexNotAnchoredToBeginning()
    {
        var pattern = new HighPerformancePattern("ABCD", "[A-Z]+", 1, 5, 6);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsSignatureTooShort()
    {
        var pattern = new HighPerformancePattern("AB", "^[A-Z]+", 1, 5, 6);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsSignatureTooLong()
    {
        var pattern = new HighPerformancePattern("ABCDE", "^[A-Z]+", 1, 5, 6);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsSignatureWithNonAsciiChars()
    {
        var pattern = new HighPerformancePattern("AB€", "^[A-Z]+", 1, 5, 6);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsMaxMatchLengthShorterThanMinMatchLength()
    {
        var pattern = new HighPerformancePattern("ABCD", "^[A-Z]+", 1, 5, 4);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsNegativeSignaturePrefixLength()
    {
        var pattern = new HighPerformancePattern("ABC", "^[A-Z]+", -1, 5, 6);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsNegativeMinMatchLength()
    {
        var pattern = new HighPerformancePattern("ABC", "^[A-Z]+", 1, -1, 6);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsNegativeMaxMatchLength()
    {
        var pattern = new HighPerformancePattern("ABC", "^[A-Z]+", 1, 5, -1);
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsMinMatchLengthSmallerThanSignaturePrefixPlusSignatureLength()
    {
        var pattern = new HighPerformancePattern("ABC", "^[A-Z]+", 2, 4, 5);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    [TestMethod]
    public void CompiledHighPerformancePattern_CodeGenDisallowsThreeCharSignatureAtEndOfInput()
    {
        var pattern = new HighPerformancePattern("ABC", "^[A-Z]+", 0, 3, 5);
        Assert.ThrowsException<ArgumentException>(() => CompiledHighPerformancePattern.GenerateAdditionalCode([pattern]));
    }

    // Check that there's no way to use existing high-performance patterns and
    // produce input that would trigger false negatives if we skipped matching
    // signatures in the high-performance scanner even when the subsequent regex
    // match fails.
    //
    // We no longer actually rely on this as an invariant and there is now
    // deliberate code and a unit test to for the case where this doesn't hold.
    //
    // If this test fails when adding a new pattern:
    //
    //  1. Delete the parenthetical comment in HighPerformanceScanner.cs that
    //     says that this is not currently possible even though we are prepared
    //     for it.
    //
    //  2. Improve HighPerformanceScanner_OverlappingSignatures test or author a
    //     new test of overlapping signatures using actual product patterns and
    //     signatures.
    //
    //  3. Delete this test.
    [TestMethod]
    public void CompiledHighPerformancePattern_NoOverlappingSignaturesYet()
    {
        var signatures = new HashSet<string>(CompiledHighPerformancePattern.EnumerateAllHighPerformancePatterns().Select(p => p.Signature));

        foreach (string signature in signatures)
        {
            foreach (string other in signatures)
            {
                if (signature == other)
                {
                    continue;
                }

                if (other == "ab85" && CompiledHighPerformancePattern.ForSignature(other).ScopedRegex.ToString().StartsWith("^secret_scanning_"))
                {
                    // This is one overlapping signature case that does exist
                    // today: '+ABa' and 'ab85' can overlap but then +ABa can't
                    // match the secret_scanning_ expected before immediately
                    // before ab85 so it's insufficient to produce a real test
                    // case.
                    continue;
                }

                for (int i = 1; i < signature.Length; i++)
                {
                    string prefix = signature.Substring(i);
                    Assert.IsFalse(other.StartsWith(prefix), ($"Signature '{signature}' can overlap with signature '{other}'."));
                }
            }
        }
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
#endif

    private static string GetGeneratedFilePath([CallerFilePath] string path = "")
    {
        path = Path.GetDirectoryName(path);
        path = Path.Combine(path,
                            "..",
                            "Microsoft.Security.Utilities.Core",
                            $"{nameof(CompiledHighPerformancePattern)}.Generated.cs");
        return path;
    }
}
