// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities;

/// <summary>
/// A pattern that <see cref="HighPerformanceScanner"/> can scan for.
/// </summary>
/// <remarks>
/// There is one instance per signature of patterns that implement <see
/// cref="IHighPerformanceScannableKey"/>, which is pre-computed using code
/// generation. Apart from unit tests, no other instances are created.
/// </remarks>
internal sealed partial class CompiledHighPerformancePattern
{


    /// <summary>
    /// The signature that identifies this pattern. This data must be found in
    /// the input using a fast, initial search operation; otherwise the regex
    /// will not be applied.
    /// </summary>
    public string Signature { get; }

    /// <summary>
    /// The fixed number of characters that appear before the signature in a match.
    /// </summary>
    public int SignaturePrefixLength { get; }

    /// <summary>
    /// The minimum number of characters that can appear in a match.
    /// </summary>
    public int MinMatchLength { get; }

    /// <summary>
    /// The maximum number of characters that can appear in a match.
    /// </summary>
    public int MaxMatchLength { get; }

    /// <summary>
    /// The regular expression that matches the pattern near a signature.
    /// <summary>
    /// <remarks>
    /// WARNING: This is distinct from the general regexes for this pattern that
    /// can be applied to find all matches in an arbitrary input. This regex is
    /// not run on the entire input but only on a substring determined by <see
    /// cref="SignaturePrefixLength"/> and <see cref="MaxMatchLength"/>.
    ///
    /// The regex must also be anchored to the beginning of the input.
    ///
    /// The regex may assume that the signature is present at the expected
    /// location. This can allow regexes to be shared that would differ only by
    /// signature.
    /// </remarks>
    public Regex ScopedRegex { get; }

    /// <summary>
    /// A rendering of the signature for fast, allocation-free lookup.
    /// </summary>
    /// <remarks>
    /// This is implemented by packing the 3-4 byte ASCII bytes of the signature
    /// into an integer, with the leftmost signature character in the least
    /// signficant byte. However, this encoding should be considered an
    /// implementation detail that can change.
    /// </remarks>
    public int PackedSignature { get; }

    /// <summary>
    /// Gets the pre-computed pattern for the given signature or null if there is none.
    /// </summary>
    public static CompiledHighPerformancePattern? ForSignature(string signature)
    {
        return s_patternsBySignature.TryGetValue(signature, out CompiledHighPerformancePattern? pattern) ? pattern : null;
    }

    /// <summary>
    /// Regex options used for all high-performance regexes.
    /// </summary>
    /// <remarks>
    /// We don't use 'NonBacktracking' here because it is not supported by the
    /// regex source generator. However these high-performance patterns should
    /// not cause problematic backtracking. They are extremely simple, anchored
    /// to the front with at most one optional group at the end. Generated code
    /// has been inspected to see that the only "loops" have at most 1
    /// iteration. If more complex regexes are added, the generated code should
    /// be re-examined.
    ///
    /// 'SingleLine' is used to ensure that '.' matches any character including
    /// new lines. This is used to share regexes that can purely skip over the
    /// signature that has already been matched before the regex is applied.
    ///
    /// Also note that the high-performance scanner does not allow substitution
    /// of the regex engine and the regex engine built-in to .NET is always
    /// used. Profiling showed no performance gain from RE2, even on .NET
    /// Framework, even for the unoptimized 'SecretMasker' using only the
    /// highly-identifiable patterns, but this merits more scrutiny and
    /// investigation.
    ///
    /// Even more critically, the regex engine abstraction does not currently
    /// provide a mechanism to search within a substring without allocation.
    /// There is no incentive to add it, which would require work in the RE2
    /// wrapper, unless further investigation reveals a flaw in the finding on
    /// RE2 performance above.
    /// </remarks>
    private const RegexOptions Options = RegexOptions.Compiled |
                                         RegexOptions.ExplicitCapture |
                                         RegexOptions.CultureInvariant |
                                         RegexOptions.Singleline;


    public CompiledHighPerformancePattern(string signature,
                                          int signaturePrefixLength,
                                          int minMatchLength,
                                          int maxMatchLength,
                                          Regex scopedRegex)
    {
#if HIGH_PERFORMANCE_CODEGEN // This validation happens at compile time and needn't be repeated at runtime.
        if (!scopedRegex.ToString().StartsWith("^"))
        {
            throw new ArgumentException($"The regular expression must be anchored to the beginning of the input: '{scopedRegex}'", nameof(scopedRegex));
        }

        if (signature.Length != 3 && signature.Length != 4)
        {
            throw new ArgumentException($"The signature must be 3 or 4 characters long: '{signature}'.", nameof(signature));
        }
#endif
        char s0 = signature[0];
        char s1 = signature[1];
        char s2 = signature[2];
        char s3 = signature.Length < 4 ? '\0' : signature[3];

#if HIGH_PERFORMANCE_CODEGEN
        if (s0 > 0x7F || s1 > 0x7F || s2 > 0x7F || s3 > 0x7F)
        {
            throw new ArgumentException($"The signature must consist entirely of ASCII characters: '{signature}'.", nameof(signature));
        }
#endif

        int packedSignature = s0 | (s1 << 8) | (s2 << 16);
        if (signature.Length == 4)
        {
            packedSignature |= (s3 << 24);
        }

        Signature = signature;
        SignaturePrefixLength = signaturePrefixLength;
        MinMatchLength = minMatchLength;
        MaxMatchLength = maxMatchLength;
        ScopedRegex = scopedRegex;
        PackedSignature = packedSignature;
    }

#if HIGH_PERFORMANCE_CODEGEN
    // TODO: Use Roslyn generator: https://github.com/microsoft/security-utilities/issues/152
    /// <summary>
    /// This is invoked by T4 via reflection to produce the generated portion of
    /// this class, which enumerates all the patterns that implement <see
    /// cref="IHighPerformanceScannableKey"/> and precomputes them into to <see
    /// cref="CompiledHighPerformancePattern"/>.
    ///
    /// On .NET 8+, this input is further processed by the regex source generator
    /// to pre-compile the regexes into C# source code.
    /// </summary>
    internal static string GenerateAdditionalCode()
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            """
            using System.Collections.Generic;
            using System.Linq;
            using System.Text.RegularExpressions;

            namespace Microsoft.Security.Utilities;

            partial class CompiledHighPerformancePattern
            {
            """);

        // Since patterns can share regexes, we deduplicate them and assign an ID using this counter.
        int regexId = 0;

        // Key = regex pattern, Value = regex ID.
        Dictionary<string, int> regexes = [];

        // Key = signature, Value = code to construct its CompiledHighPerformancePattern.
        Dictionary<string, string> patterns = [];

        foreach (IHighPerformanceScannableKey generalPattern in WellKnownRegexPatterns.HighConfidenceMicrosoftSecurityModels.OfType<IHighPerformanceScannableKey>())
        {
            foreach (HighPerformancePattern pattern in generalPattern.HighPerformancePatterns)
            {
                if (!regexes.TryGetValue(pattern.ScopedRegex, out int id))
                {
                    id = regexId++;
                    regexes[pattern.ScopedRegex] = id;
                }

                // Generate the call to the pattern constructor.
                string code = $"""new("{pattern.Signature}", {pattern.SignaturePrefixLength}, {pattern.MinMatchLength}, {pattern.MaxMatchLength}, Regex{id})""";

                // Also call the constructor now to catch bad inputs during code generation.
                new CompiledHighPerformancePattern(
                    pattern.Signature,
                    pattern.SignaturePrefixLength,
                    pattern.MinMatchLength,
                    pattern.MaxMatchLength,
                    new Regex(pattern.ScopedRegex, Options));

                if (patterns.TryGetValue(pattern.Signature, out string? existingCode))
                {
                    if (code != existingCode)
                    {
                        throw new InvalidOperationException(
                            $"""
                            There are multiple patterns for '{pattern.Signature}' that generate different code.
                            This is not supported.

                            < {existingCode}
                            > {code}
                            """);
                    }
                    continue;
                }

                patterns.Add(pattern.Signature, code);
            }
        }

        foreach (KeyValuePair<string, int> regex in regexes.OrderBy(p => p.Value))
        {
            sb.AppendLine($""""    /*lang=regex*/ private const string RawRegex{regex.Value} = """{regex.Key}""";"""");
        }

        sb.AppendLine();

        foreach (int id in regexes.Values.OrderBy(v => v))
        {
            sb.AppendLine($"""    private static readonly Regex Regex{id} = GetRegex{id}();""");
        }

        sb.AppendLine();
        sb.AppendLine("""    private static readonly CompiledHighPerformancePattern[] s_patterns = [""");

        foreach (string pattern in patterns.Values.OrderBy(v => v))
        {
            sb.AppendLine($"""        {pattern},""");
        }

        sb.AppendLine("""    ];""");
        sb.AppendLine();
        sb.AppendLine("""    private static readonly Dictionary<string, CompiledHighPerformancePattern> s_patternsBySignature = s_patterns.ToDictionary(p => p.Signature);""");
        sb.AppendLine();
        sb.AppendLine("#if NET8_0_OR_GREATER");

        foreach (int id in regexes.Values.OrderBy(v => v))
        {
            sb.AppendLine($"""    [GeneratedRegex(RawRegex{id}, Options)] private static partial Regex GetRegex{id}();""");
        }

        sb.AppendLine("#else");

        foreach (int id in regexes.Values.OrderBy(v => v))
        {
            sb.AppendLine($"""    private static Regex GetRegex{id}() => new(RawRegex{id}, Options);""");
        }

        sb.AppendLine("#endif");
        sb.AppendLine("}");

        return sb.ToString();
    }
#endif
}
