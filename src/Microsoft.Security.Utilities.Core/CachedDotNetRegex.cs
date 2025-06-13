// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text.RegularExpressions;

namespace Microsoft.Security.Utilities
{
    /// <summary>
    ///  CachedDotNetRegex is an IRegex implementation which pre-compiles all Regexes and then
    ///  calls through to .NET's System.Text.RegularExpressions.Regex.
    /// </summary>
    public class CachedDotNetRegex : IRegexEngine
    {
        public static IRegexEngine Instance { get; } = new CachedDotNetRegex();

        internal static TimeSpan DefaultTimeout = TimeSpan.FromMilliseconds(int.MaxValue - 1);

        private CachedDotNetRegex()
        {
        }

        internal static ConcurrentDictionary<(string Pattern, RegexOptions Options), Regex> RegexCache { get; } = new();

        public static Regex GetOrCreateRegex(string pattern, RegexOptions? options = null)
        {
            (string, RegexOptions) key = (pattern, options ?? RegexDefaults.DefaultOptions);
            return RegexCache.GetOrAdd(key, key => new Regex(NormalizeGroupsPattern(key.Pattern), key.Options));
        }

        internal static string NormalizeGroupsPattern(string pattern)
        {
            return pattern.Replace("?P<", "?<");
        }

        public IEnumerable<UniversalMatch> Matches(string input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            Regex regex = GetOrCreateRegex(pattern, options);
            foreach (Match m in regex.Matches(input))
            {
                yield return CreateUniversalMatch(captureGroup: captureGroup, match: m);

                // Instance Regex.Matches has no overload; check timeout between matches
                // (MatchCollection *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }
        }

#if NET
        public IEnumerable<UniversalMatch> Matches(ReadOnlySpan<char> input, string pattern, RegexOptions? options = null, TimeSpan timeout = default, string captureGroup = null)
        {
            if (timeout == default) { timeout = DefaultTimeout; }
            var w = Stopwatch.StartNew();

            // Using a list because ValueMatchEnumerator is a ref struct and can't cross yield boundaries.
            List<UniversalMatch> list = null;
            Regex regex = GetOrCreateRegex(pattern, options);

            foreach (ValueMatch m in regex.EnumerateMatches(input))
            {
                list ??= new();
                list.Add(CreateUniversalMatch(m, captureGroup, regex, input));

                // Instance Regex.EnumerateMatches has no overload; check timeout between matches
                // (ValueMatchEnumerator *is* lazily computed).
                if (w.Elapsed > timeout) { break; }
            }

            return (IEnumerable<UniversalMatch>)list ?? Array.Empty<UniversalMatch>();
        }

        private static UniversalMatch CreateUniversalMatch(ValueMatch match, string captureGroup, Regex regex, ReadOnlySpan<char> input)
        {
            if (captureGroup == null)
            {
                return CreateUniversalMatchWithNoCapture(match, input);
            }

            // https://github.com/dotnet/runtime/issues/73223: There is no
            // capture group support when matching against a span. Workaround:
            // rerun the match against a substring that contains only the match.
            Match rematch = regex.Match(input.Slice(match.Index, match.Length).ToString());
            Debug.Assert(rematch.Success && rematch.Index == 0 && rematch.Length == match.Length, "Rematch should succeed and produce same result.");
            UniversalMatch universalMatch = CreateUniversalMatch(rematch, captureGroup);
            universalMatch.Index += match.Index; // Adjust index to be relative to original input
            return universalMatch;
        }

        private static UniversalMatch CreateUniversalMatchWithNoCapture(ValueMatch match, ReadOnlySpan<char> input)
        {
            return new UniversalMatch
            {
                Success = true,
                Index = match.Index,
                Length = match.Length,
                Value = input.Slice(match.Index, match.Length).ToString()
            };
        }
#endif

        private static UniversalMatch CreateUniversalMatch(Match match, string captureGroup)
        {
            // NOTE: Value property allocates. Don't call it twice when there's
            // a capture. With more refactoring, we could and should eliminate
            // the Value property on UniversalMatch and encourage callers to
            // work with the text in the matched range without allocating a
            // substring.
            Group group = match;

            if (captureGroup != null)
            {
                Group capture = match.Groups[captureGroup];
                if (capture.Success)
                {
                    group = capture;
                }
            }

            return new UniversalMatch
            {
                Success = group.Success, 
                Index = group.Index,
                Length = group.Length,
                Value = group.Value
            };
        }
    }
}
