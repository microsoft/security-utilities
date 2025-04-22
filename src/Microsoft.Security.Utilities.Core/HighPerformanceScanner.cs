// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text.RegularExpressions;

#if NET8_0_OR_GREATER
using System.Buffers;
using StringInput = System.ReadOnlySpan<char>;
#else
using StringInput = string;
#endif

namespace Microsoft.Security.Utilities;

/// <summary>
/// A scanner that is optimized to match patterns that implement <see
/// cref="IHighPerformanceScannableKey"/>.
///
/// The input is walked in one pass for all patterns, looking for 3-4 char
/// signatures. When a signature is found, a corresponding pattern is looked up
/// and its regex is applied to a substring of the appropriate size nearby.
/// </summary>
internal sealed class HighPerformanceScanner
{
    private Dictionary<int, CompiledHighPerformancePattern> _patternsByPackedSignature = new();

#if NET9_0_OR_GREATER
    private static SearchValues<string> s_emptySignatures = SearchValues.Create(Array.Empty<string>(), StringComparison.Ordinal);
    private SearchValues<string> _signatures = s_emptySignatures;
#elif NET8_0_OR_GREATER
    private static SearchValues<char> s_emptySignatureStarts = SearchValues.Create(Array.Empty<char>());
    private SearchValues<char> _signatureStarts = s_emptySignatureStarts;
#else
    private char[] _signatureStarts = Array.Empty<char>();
#endif

    public HighPerformanceScanner()
    {
    }

    public HighPerformanceScanner(IEnumerable<CompiledHighPerformancePattern> patterns)
    {
        AddPatterns(patterns);
    }

    public void AddPatterns(IEnumerable<CompiledHighPerformancePattern> patterns)
    {
        foreach (CompiledHighPerformancePattern newPattern in patterns)
        {
            Debug.Assert(!_patternsByPackedSignature.TryGetValue(newPattern.PackedSignature, out var p) || p == newPattern, "Multiple compiled high-performance patterns with same packed signature.");
            _patternsByPackedSignature[newPattern.PackedSignature] = newPattern;
        }

        IEnumerable<CompiledHighPerformancePattern> allPatterns = _patternsByPackedSignature.Values;
#if NET9_0_OR_GREATER
        _signatures = SearchValues.Create(allPatterns.Select(p => p.Signature).ToArray(), StringComparison.Ordinal);
#elif NET8_0_OR_GREATER
        _signatureStarts = SearchValues.Create(allPatterns.Select(p => p.Signature[0]).Distinct().ToArray());
#else
        _signatureStarts = allPatterns.Select(p => p.Signature[0]).Distinct().ToArray();
#endif
    }

    /// <summary>
    /// Scan the input for all patterns and return the detections found.
    /// </summary>
    public List<HighPerformanceDetection> Scan(StringInput input)
    {
        if (input.Length == 0)
        {
            return [];
        }

        var detections = new List<HighPerformanceDetection>();
        int index = 0;
        do
        {
            CompiledHighPerformancePattern? pattern = FindNextSignature(input, ref index);
            if (pattern == null)
            {
                break;
            }

            if (Match(pattern, input, index, out HighPerformanceDetection detection))
            {
                detections.Add(detection);
            }

            index += pattern.Signature.Length;
        } while (index < input.Length);

        return detections;
    }

    /// <summary>
    /// Match the given pattern in the input where the given index is known to
    /// be be positioned at the pattern's signature. If successful, return true
    /// with a detection to be returned to the caller. Otherwise, return false.
    /// </summary>
    private static bool Match(CompiledHighPerformancePattern pattern,
                              StringInput input,
                              int index,
                              out HighPerformanceDetection detection)
    {
        detection = default;

        int start = index - pattern.SignaturePrefixLength;
        if (start < 0)
        {
            return false;
        }

        int end = Math.Min(input.Length, index + pattern.MaxMatchLength);
        int length = end - start;
        if (length < pattern.MinMatchLength)
        {
            return false;
        }

#if NET8_0_OR_GREATER
        // This API is non-allocating, but only available in .NET 8.0 and later.
        Regex.ValueMatchEnumerator matches = pattern.ScopedRegex.EnumerateMatches(input.Slice(start, length));
        if (!matches.MoveNext())
        {
            return false;
        }
        ValueMatch match = matches.Current;
        Debug.Assert(match.Index == 0, "The regex should be anchored to the beginning.");
#else
        Match match = pattern.ScopedRegex.Match(input, start, length);
        if (!match.Success)
        {
            return false;
        }
        Debug.Assert(match.Index == start, "The regex should be anchored to the beginning.");
#endif

        length = match.Length;
        detection = new HighPerformanceDetection(pattern.Signature, start, match.Length);
        return true;
    }

    /// <summary>
    /// Find the next signature in the input starting at the given index. If
    /// successful, adjust the index to the start of the signature and return
    /// the corresponding pattern. Otherwise, return null.
    ///
    /// The performance of this method is highly sensitive to the version of
    /// .NET that is used.
    /// </summary>
    private CompiledHighPerformancePattern? FindNextSignature(StringInput input, ref int index)
    {
#if NET9_0_OR_GREATER
        // .NET 9: This API is *highly* optimized when searching for small ASCII
        //  substrings as we do. It uses the 'Teddy' algorithm:
        //  https://github.com/dotnet/runtime/blob/c1fe87ad88532f0e80de3739fe7b215e6e1f8b90/src/libraries/System.Private.CoreLib/src/System/SearchValues/Strings/AsciiStringSearchValuesTeddyBase.cs#L17
        //  https://github.com/BurntSushi/aho-corasick/blob/8d735471fc12f0ca570cead8e17342274fae6331/src/packed/teddy/README.md
        int offset = input.Slice(index).IndexOfAny(_signatures);
        if (offset < 0)
        {
            return null;
        }
        index += offset;
        CompiledHighPerformancePattern? pattern = GetPatternForSignature(input, index);
        return pattern;
#else
        while (true)
        {
#if NET8_0_OR_GREATER
            // .NET 8: This API is *highly* optimized but can only find a single
            // character. We use it to find the next signature start character.
            // Then we must check if there is actually a signature at that
            // location and loop if not.
            int offset = input.Slice(index).IndexOfAny(_signatureStarts);
            if (offset < 0)
            {
                return null;
            }
            index += offset;
#else
            // .NET Framework: Same approach as .NET 8 using plain old
            // string.IndexOfAny for next signature character.
            index = input.IndexOfAny(_signatureStarts, index);
            if (index < 0)
            {
                return null;
            }
#endif

            CompiledHighPerformancePattern? pattern = GetPatternForSignature(input, index);
            if (pattern == null)
            {
                index++;
                continue;
            }

            return pattern;
        }
#endif
    }

    /// <summary>
    /// If the input at the given index starts with a known signature, return
    /// the corresponding pattern, otherwise return null. The lookup is done by
    /// packing 3 and 4 ASCII characters into integers and looking them up in
    /// a dictionary indexed by packed signatures.
    /// </summary>
    private CompiledHighPerformancePattern? GetPatternForSignature(StringInput input, int index)
    {
        if ((input.Length - index) < 4)
        {
            // Although some patterns have 3 only character signatures, they would
            // never match if the signature appears at the end of the input, so we
            // can require 4 characters to be present here.
            return null;
        }

        char s0 = input[index];
        char s1 = input[index + 1];
        char s2 = input[index + 2];
        char s3 = input[index + 3];

        Debug.Assert(s0 <= 0x7F, "This is called when finding a leading signature char, which must be ASCII");

        if (s1 > 0x7F || s2 > 0x7F || s3 > 0x7F)
        {
            // Non-ASCII characters: not a signature. This is true even for
            // 3-character signatures, as those patterns expect at least one
            // ASCII character after the signature.
            return null;
        }

        int shortPackedSignature = s0 | (s1 << 8) | (s2 << 16);
        int longPackedSignature = shortPackedSignature | (s3 << 24);

        if (!_patternsByPackedSignature.TryGetValue(longPackedSignature, out CompiledHighPerformancePattern? pattern)
            && !_patternsByPackedSignature.TryGetValue(shortPackedSignature, out pattern))
        {
            return null;
        }

        return pattern;
    }
}